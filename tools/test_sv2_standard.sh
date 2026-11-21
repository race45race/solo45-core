#!/bin/bash
# Stratum V2 standard channels end to end on the private regtest chain (stand: bash tools/sv2_regtest.sh start):
# Core's own test miner opens a standard channel (header-only mining, like Braiins OS) over encrypted SV2 and mines
# 3 shares; on regtest each one is a block. Passes when the node's height went up by 3, the blocks pay the payout
# address and at least one of them carries the test transactions sent first.
set -u
B=$HOME/solo45-test/bitcoin-32.1/bin/bitcoin-cli
N="-regtest -datadir=$HOME/solo45-test/regtest-node -rpcport=18543"
ADDR=$(cat $HOME/solo45-test/core-regtest/address.txt)
CORE=$HOME/solo45-core/target/release/solo45-core
for i in $(seq 1 8); do $B $N -rpcwallet=core-test sendtoaddress $ADDR 0.01 > /dev/null; done
H0=$($B $N getblockcount)
PUB=$(python3 -c 'import json,os; print(json.load(open(os.path.expanduser("~/solo45-test/core-sv2/sv2-authority.json")))["public"])')
timeout 120 $CORE sv2-miner 127.0.0.1:34260 $PUB "$ADDR.stdminer" 3 | grep -v '^share'
sleep 1
H1=$($B $N getblockcount)
SPK=$($B $N getaddressinfo $ADDR | python3 -c 'import json,sys; print(json.load(sys.stdin)["scriptPubKey"])')
pass=1
[ $((H1 - H0)) -eq 3 ] || { echo "FAIL: height $H0 -> $H1 (expected +3)"; pass=0; }
with_txs=0
for h in $(seq $((H0 + 1)) $H1); do
  out=$($B $N getblock $($B $N getblockhash $h) 2 | python3 -c 'import json,sys
b = json.load(sys.stdin)
pays = any(o["scriptPubKey"]["hex"] == sys.argv[1] for o in b["tx"][0]["vout"])
print(len(b["tx"]), "pays" if pays else "WRONG-PAYOUT")' "$SPK")
  echo "block $h: $out"
  case "$out" in *WRONG-PAYOUT*) pass=0;; esac
  [ "${out%% *}" -gt 1 ] && with_txs=$((with_txs + 1))
done
[ $with_txs -ge 1 ] || { echo "FAIL: no block carried the test transactions"; pass=0; }
[ $pass = 1 ] && echo "standard channels: PASS (3 blocks, $with_txs with transactions)" || { echo "standard channels: FAIL"; exit 1; }
