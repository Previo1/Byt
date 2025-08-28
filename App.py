from flask import Flask, render_template, request, jsonify
import hashlib
import time
import secrets

app = Flask(__name__)

# ---------------- Config / Chain State ---------------- #
DIFFICULTY = 4
INITIAL_REWARD = 50.0
HALVING_INTERVAL = 2 * 365 * 24 * 60 * 60  # 2 years in seconds
TOTAL_SUPPLY_CAP = 1_000_000.0

# chain state
chain = []
mempool = []  # list of pending transactions
wallets = {}  # address -> {"private":..., "balance":...}
balances = {}  # address -> float (confirmed balance)
circulating_supply = 0.0
network_start_time = time.time()

# ---------------- Helpers ---------------- #
def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def create_wallet():
    addr = "addr_" + secrets.token_hex(8)
    private = secrets.token_hex(32)
    wallets[addr] = {"private": private}
    # ensure balances entry
    balances.setdefault(addr, 0.0)
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
    # sum of amounts (plus fees if you add) in mempool from this addr
    s = 0.0
    for tx in mempool:
        if tx["from"] == addr:
            s += float(tx["amount"])
    return s

def available_balance_for_new_tx(addr):
    return get_confirmed_balance(addr) - get_pending_outgoing(addr)

def create_tx(from_addr, to_addr, amount, priv):
    # basic checks
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
        return False, "Insufficient available balance (pending tx considered)"
    tx = {
        "from": from_addr,
        "to": to_addr,
        "amount": round(amount, 8),
        "timestamp": time.time()
    }
    # txid = hash of tx
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
    # apply confirmed transfer
    frm = tx["from"]
    to = tx["to"]
    amt = float(tx["amount"])
    # subtract from sender
    balances[frm] = round(balances.get(frm, 0.0) - amt, 8)
    # add to receiver
    balances[to] = round(balances.get(to, 0.0) + amt, 8)

def mine_block(miner_address, max_txs=100):
    global circulating_supply
    # check supply cap
    if circulating_supply >= TOTAL_SUPPLY_CAP:
        return False, "Max supply reached"

    # collect transactions (simple FIFO)
    txs_to_include = mempool[:max_txs]

    # create coinbase tx (reward)
    reward = get_current_reward()
    # adjust if final partial reward required
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
    # proof-of-work
    while True:
        block_string = str(block["index"]) + block["previous_hash"] + str(block["timestamp"]) + str(block["transactions"]) + str(block["nonce"])
        h = sha256(block_string)
        if h.startswith(target_prefix):
            block["hash"] = h
            break
        block["nonce"] += 1

    # commit block: apply coinbase reward & apply transactions (ensure validity)
    # apply coinbase
    balances.setdefault(miner_address, 0.0)
    balances[miner_address] = round(balances[miner_address] + reward, 8)
    circulating_supply = round(circulating_supply + reward, 8)

    # apply included txs (we must validate they still have sufficient confirmed balance)
    # For simplicity: when tx was created we already reserved via pending outgoing check.
    # But confirmed balances may have changed if other blocks mined earlier included some of same sender txs.
    # We'll attempt to apply and skip invalid ones.
    applied = []
    skipped = []
    for tx in txs_to_include:
        frm = tx["from"]
        to = tx["to"]
        amt = float(tx["amount"])
        # validate sender has enough confirmed balance now
        if balances.get(frm, 0.0) >= amt:
            apply_transaction(tx)
            applied.append(tx)
        else:
            skipped.append(tx)

    # remove applied/skipped txs from mempool (we remove by txid)
    new_mempool = []
    included_txids = set([t["txid"] for t in applied + skipped])
    for tx in mempool:
        if tx["txid"] not in included_txids:
            new_mempool.append(tx)
    # note: skipped txs are removed from mempool (miner considered them and skipped)
    mempool[:] = new_mempool

    chain.append(block)
    return True, {
        "block": block,
        "applied_count": len(applied),
        "skipped_count": len(skipped)
    }

# ---------------- Init chain ---------------- #
chain.append(create_genesis_block())

# ---------------- Flask Routes / API ---------------- #
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/wallet/create", methods=["POST"])
def api_wallet_create():
    addr, priv = create_wallet()
    return jsonify({"address": addr, "private": priv})

@app.route("/api/wallets", methods=["GET"])
def api_wallets_list():
    # return list of wallets with balances (do NOT return private keys here)
    out = []
    for a in wallets:
        out.append({"address": a, "balance": get_confirmed_balance(a)})
    return jsonify({"wallets": out})

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
    # ensure miner wallet exists (auto create if not)
    if not wallet_exists(miner):
        # auto create but user won't have private key stored if auto-created here
        wallets[miner] = {"private": None}
        balances.setdefault(miner, 0.0)

    ok, resp = mine_block(miner)
    if not ok:
        return jsonify({"success": False, "reason": resp}), 200
    return jsonify({"success": True, "block": resp["block"], "applied": resp["applied_count"], "skipped": resp["skipped_count"]})

@app.route("/api/chain", methods=["GET"])
def api_chain():
    return jsonify({"chain": chain, "circulating_supply": circulating_supply, "total_supply": TOTAL_SUPPLY_CAP, "difficulty": DIFFICULTY, "current_reward": get_current_reward()})

@app.route("/api/balance/<address>", methods=["GET"])
def api_balance(address):
    return jsonify({"address": address, "balance": get_confirmed_balance(address), "available": available_balance_for_new_tx(address)})

@app.route("/api/validate", methods=["GET"])
def api_validate():
    # basic validate: check prev hashes and recompute hash
    for i in range(1, len(chain)):
        curr = chain[i]
        prev = chain[i-1]
        if curr["previous_hash"] != prev["hash"]:
            return jsonify({"valid": False, "reason": f"prev hash mismatch at {i}"})
        # recompute hash
        block_string = str(curr["index"]) + curr["previous_hash"] + str(curr["timestamp"]) + str(curr["transactions"]) + str(curr["nonce"])
        if sha256(block_string) != curr["hash"]:
            return jsonify({"valid": False, "reason": f"hash mismatch at {i}"})
    return jsonify({"valid": True})

# ---------------- Run app ---------------- #
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
