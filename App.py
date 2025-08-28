# app.py
from flask import Flask, render_template, request, jsonify
import hashlib
import time
import secrets
import os
import json
import getpass
from base64 import urlsafe_b64encode, urlsafe_b64decode

# cryptography imports for encryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

app = Flask(__name__)

# ---------------- Config / Chain State ---------------- #
DIFFICULTY = 4
INITIAL_REWARD = 50.0
HALVING_INTERVAL = 2 * 365 * 24 * 60 * 60  # 2 years in seconds
TOTAL_SUPPLY_CAP = 1_000_000.0

WALLETS_FILE = "wallets.dat"  # encrypted wallet store

# chain state
chain = []
mempool = []  # list of pending transactions
wallets = {}  # address -> {"private":...}  (loaded encrypted)
balances = {}  # address -> float (confirmed balance)
circulating_supply = 0.0
network_start_time = time.time()

# ---------------- Encryption Helpers (persistent wallets) ---------------- #
def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from passphrase and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = kdf.derive(passphrase.encode())
    return urlsafe_b64encode(key)  # Fernet key

def save_wallets_to_disk(passphrase: str):
    """Encrypt `wallets` dict and save to WALLETS_FILE. Stores salt (16 bytes) + ciphertext."""
    try:
        data = json.dumps(wallets).encode()
        # generate new salt each save (or reuse? we include new salt)
        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)
        f = Fernet(key)
        ciphertext = f.encrypt(data)
        # write salt + ciphertext
        with open(WALLETS_FILE, "wb") as fh:
            fh.write(salt + ciphertext)
        app.logger.info("Wallets saved (encrypted) to %s", WALLETS_FILE)
        return True
    except Exception as e:
        app.logger.error("Failed to save wallets: %s", e)
        return False

def load_wallets_from_disk(passphrase: str):
    """Load and decrypt WALLETS_FILE into `wallets`. Returns True on success, False otherwise."""
    global wallets
    if not os.path.exists(WALLETS_FILE):
        app.logger.info("Wallet file not found, starting with empty wallets.")
        wallets = {}
        return True
    try:
        with open(WALLETS_FILE, "rb") as fh:
            raw = fh.read()
        if len(raw) < 17:
            app.logger.error("Wallet file corrupt or too small.")
            return False
        salt = raw[:16]
        ciphertext = raw[16:]
        key = derive_key(passphrase, salt)
        f = Fernet(key)
        plaintext = f.decrypt(ciphertext)
        wallets = json.loads(plaintext.decode())
        # ensure balances entries exist for loaded wallets
        for a in wallets.keys():
            balances.setdefault(a, 0.0)
        app.logger.info("Wallets loaded from disk (%d wallets).", len(wallets))
        return True
    except Exception as e:
        app.logger.error("Failed to load wallets: %s", e)
        return False

def get_passphrase():
    """Get passphrase from env or console prompt."""
    env = os.environ.get("WALLET_PASSPHRASE")
    if env:
        return env
    # if running in production without env variable, you will be prompted in console
    # note: if server started by systemd or similar without tty, this will hang — set ENV instead.
    try:
        p = getpass.getpass("Enter wallet passphrase (will be used to encrypt/decrypt wallets): ")
        return p
    except Exception:
        # fallback to empty (not secure) if prompt fails
        return ""

# ---------------- Helpers ---------------- #
def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def create_wallet(persist=True, passphrase_for_save=None):
    addr = "addr_" + secrets.token_hex(8)
    private = secrets.token_hex(32)
    wallets[addr] = {"private": private}
    balances.setdefault(addr, 0.0)
    # persist right away if passphrase provided
    if persist and passphrase_for_save:
        save_wallets_to_disk(passphrase_for_save)
    return addr, private

def wallet_exists(addr):
    return addr in wallets

def get_current_reward():
    elapsed = time.time() - network_start_time
    halvings = int(elapsed // HALVING_INTERVAL)
    reward = INITIAL_REWARD / (2 ** halvings)
    return max(reward, 0.0001)

def get_confirmed_balance(addr):
    return round(balances.get(addr, 0.0), 8)

def get_pending_outgoing(addr):
    s = 0.0
    for tx in mempool:
        if tx["from"] == addr:
            s += float(tx["amount"])
    return s

def available_balance_for_new_tx(addr):
    return get_confirmed_balance(addr) - get_pending_outgoing(addr)

def create_tx(from_addr, to_addr, amount, priv):
    if not wallet_exists(from_addr):
        return False, "Sender wallet not found"
    if wallets[from_addr]["private"] != priv:
        return False, "Invalid private key"
    if not wallet_exists(to_addr):
        return False, "Recipient wallet not found"
    try:
        amount = float(amount)
    except:
        return False, "Invalid amount"
    if amount <= 0:
        return False, "Amount must be > 0"
    if available_balance_for_new_tx(from_addr) < amount:
        return False, "Insufficient available balance (pending txs considered)"
    tx = {
        "from": from_addr,
        "to": to_addr,
        "amount": round(amount, 8),
        "timestamp": time.time()
    }
    tx["txid"] = sha256(f'{tx["from"]}{tx["to"]}{tx["amount"]}{tx["timestamp"]}{secrets.token_hex(6)}')
    mempool.append(tx)
    return True, tx

# ---------------- Block / Chain ---------------- #
def create_genesis_block():
    genesis = {
        "index": 0,
        "timestamp": time.time(),
        "previous_hash": "0",
        "nonce": 0,
        "transactions": [],
        "hash": None,
        "reward": 0.0
    }
    genesis["hash"] = sha256(str(genesis["index"]) + genesis["previous_hash"] + str(genesis["timestamp"]))
    return genesis

def get_latest_block():
    return chain[-1]

def apply_transaction(tx):
    frm = tx["from"]
    to = tx["to"]
    amt = float(tx["amount"])
    balances[frm] = round(balances.get(frm, 0.0) - amt, 8)
    balances[to] = round(balances.get(to, 0.0) + amt, 8)

def mine_block(miner_address, max_txs=100):
    global circulating_supply
    if circulating_supply >= TOTAL_SUPPLY_CAP:
        return False, "Max supply reached"

    txs_to_include = mempool[:max_txs]
    reward = get_current_reward()
    if circulating_supply + reward > TOTAL_SUPPLY_CAP:
        reward = TOTAL_SUPPLY_CAP - circulating_supply

    coinbase_tx = {
        "from": "COINBASE",
        "to": miner_address,
        "amount": round(reward, 8),
        "timestamp": time.time(),
        "txid": sha256("COINBASE"+miner_address+str(time.time())+secrets.token_hex(6))
    }

    block_index = len(chain)
    prev_hash = get_latest_block()["hash"]
    block = {
        "index": block_index,
        "timestamp": time.time(),
        "previous_hash": prev_hash,
        "nonce": 0,
        "transactions": [coinbase_tx] + txs_to_include,
        "reward": reward,
        "hash": None
    }

    target_prefix = "0" * DIFFICULTY
    while True:
        block_string = str(block["index"]) + block["previous_hash"] + str(block["timestamp"]) + str(block["transactions"]) + str(block["nonce"])
        h = sha256(block_string)
        if h.startswith(target_prefix):
            block["hash"] = h
            break
        block["nonce"] += 1

    # commit
    balances.setdefault(miner_address, 0.0)
    balances[miner_address] = round(balances[miner_address] + reward, 8)
    circulating_supply = round(circulating_supply + reward, 8)

    applied = []
    skipped = []
    for tx in txs_to_include:
        frm = tx["from"]
        to = tx["to"]
        amt = float(tx["amount"])
        if balances.get(frm, 0.0) >= amt:
            apply_transaction(tx)
            applied.append(tx)
        else:
            skipped.append(tx)

    # remove applied/skipped txs from mempool
    new_mempool = []
    included_txids = set([t["txid"] for t in applied + skipped])
    for tx in mempool:
        if tx["txid"] not in included_txids:
            new_mempool.append(tx)
    mempool[:] = new_mempool

    chain.append(block)
    return True, {"block": block, "applied_count": len(applied), "skipped_count": len(skipped)}

# ---------------- Init chain & load wallets ---------------- #
chain.append(create_genesis_block())

# load passphrase & attempt to load wallets
_pass = get_passphrase()
loaded_ok = load_wallets_from_disk(_pass) if _pass is not None else load_wallets_from_disk("")

if not loaded_ok:
    app.logger.warning("Failed to load wallets with provided passphrase. Starting with empty wallets (ensure you provide correct passphrase next time).")
    wallets = {}
    # ensure balances mapping consistent
    balances = {}

# ---------------- Flask Routes / API ---------------- #
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/wallet/create", methods=["POST"])
def api_wallet_create():
    # create wallet and persist using provided server passphrase
    addr, priv = create_wallet(persist=True, passphrase_for_save=_pass)
    return jsonify({"address": addr, "private": priv})

@app.route("/api/wallets", methods=["GET"])
def api_wallets_list():
    out = []
    for a in wallets:
        out.append({"address": a, "balance": get_confirmed_balance(a)})
    return jsonify({"wallets": out})

@app.route("/api/save_wallets", methods=["POST"])
def api_save_wallets():
    # optional endpoint to force save (requires server passphrase available)
    ok = save_wallets_to_disk(_pass)
    if ok:
        return jsonify({"saved": True})
    return jsonify({"saved": False}), 500

@app.route("/api/create_tx", methods=["POST"])
def api_create_tx():
    req = request.get_json(force=True, silent=True)
    if not req:
        return jsonify({"success": False, "reason": "invalid json"}), 400
    frm = req.get("from")
    to = req.get("to")
    amount = req.get("amount")
    priv = req.get("private")
    if not all([frm, to, amount, priv]):
        return jsonify({"success": False, "reason": "missing fields"}), 400
    ok, resp = create_tx(frm, to, amount, priv)
    if ok:
        # optionally save wallets? private keys didn't change, no need
        return jsonify({"success": True, "tx": resp})
    return jsonify({"success": False, "reason": resp}), 200

@app.route("/api/mempool", methods=["GET"])
def api_mempool():
    return jsonify({"mempool": mempool})

@app.route("/api/mine", methods=["POST"])
def api_mine():
    req = request.get_json(force=True, silent=True)
    if not req:
        return jsonify({"success": False, "reason": "invalid json"}), 400
    miner = req.get("miner")
    if not miner:
        return jsonify({"success": False, "reason": "miner missing"}), 400
    if not wallet_exists(miner):
        # auto create miner wallet but no private key returned (server-only)
        wallets[miner] = {"private": None}
        balances.setdefault(miner, 0.0)
        # persist wallets (so miner address remains)
        save_wallets_to_disk(_pass)
    ok, resp = mine_block(miner)
    if not ok:
        return jsonify({"success": False, "reason": resp}), 200
    # after mining we persisted coinbase to balances, persist wallets state (addresses)
    save_wallets_to_disk(_pass)
    return jsonify({"success": True, "block": resp["block"], "applied": resp["applied_count"], "skipped": resp["skipped_count"]})

@app.route("/api/chain", methods=["GET"])
def api_chain():
    return jsonify({"chain": chain, "circulating_supply": circulating_supply, "total_supply": TOTAL_SUPPLY_CAP, "difficulty": DIFFICULTY, "current_reward": get_current_reward()})

@app.route("/api/balance/<address>", methods=["GET"])
def api_balance(address):
    return jsonify({"address": address, "balance": get_confirmed_balance(address), "available": available_balance_for_new_tx(address)})

@app.route("/api/validate", methods=["GET"])
def api_validate():
    for i in range(1, len(chain)):
        curr = chain[i]
        prev = chain[i-1]
        if curr["previous_hash"] != prev["hash"]:
            return jsonify({"valid": False, "reason": f"prev hash mismatch at {i}"})
        block_string = str(curr["index"]) + curr["previous_hash"] + str(curr["timestamp"]) + str(curr["transactions"]) + str(curr["nonce"])
        if sha256(block_string) != curr["hash"]:
            return jsonify({"valid": False, "reason": f"hash mismatch at {i}"})
    return jsonify({"valid": True})

# ---------------- Run app ---------------- #
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
