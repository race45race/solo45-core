#!/bin/bash
# Stratum V2: work that must not be used any more is replaced AT ONCE (stand: bash tools/sv2_regtest.sh start).
# A standard-channel test miner without an address in its name (it pays the pool's payout address) mines one share
# (a block on regtest) and pauses; meanwhile the payout address changes. Core must send that channel new work for
# the same block with SetNewPrevHash (so the miner drops the old jobs, like V1's clean_jobs; the node refusing a
# job takes the same path), and the next block must pay the NEW address. Puts the old payout address back after.
set -u
B=$HOME/solo45-test/bitcoin-32.1/bin/bitcoin-cli
N="-regtest -datadir=$HOME/solo45-test/regtest-node -rpcport=18543"
ADDR=$(cat $HOME/solo45-test/core-regtest/address.txt)
NEW=$($B $N -rpcwallet=core-test getnewaddress repay bech32)
CORE=$HOME/solo45-core/target/release/solo45-core
LOG=$HOME/solo45-test/core-sv2/pool.log
spk() { $B $N getaddressinfo $1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["scriptPubKey"])'; }
payout() { curl -s -X POST -H 'Content-Type: application/json' -d "{\"address\":\"$1\"}" 127.0.0.1:3389/api/payout; echo; }
PUB=$(python3 -c 'import json,os; print(json.load(open(os.path.expanduser("~/solo45-test/core-sv2/sv2-authority.json")))["public"])')
H0=$($B $N getblockcount)
OUT=$HOME/solo45-test/core-sv2/repay-miner.out
timeout 120 $CORE sv2-miner 127.0.0.1:34260 $PUB "repayminer" 2 6 > $OUT &
M=$!
for i in $(seq 1 60); do [ $($B $N getblockcount) -gt $H0 ] && break; sleep 0.5; done
sleep 1
payout $NEW
wait $M
payout $ADDR
H1=$($B $N getblockcount)
pass=1
[ $((H1 - H0)) -eq 2 ] || { echo "FAIL: height $H0 -> $H1 (expected +2)"; pass=0; }
pays() { $B $N getblock $($B $N getblockhash $1) 2 | python3 -c 'import json,sys
b = json.load(sys.stdin); print(any(o["scriptPubKey"]["hex"] == sys.argv[1] for o in b["tx"][0]["vout"]))' "$2"; }
[ "$(pays $((H0 + 1)) $(spk $ADDR))" = True ] || { echo "FAIL: block 1 doesn't pay the old address"; pass=0; }
[ "$(pays $((H0 + 2)) $(spk $NEW))" = True ] || { echo "FAIL: block 2 doesn't pay the new address"; pass=0; }
# SetNewPrevHash: one at the start, one after block 1, one for the new payout (same block) = at least 3
snph=$(grep -c '^SetNewPrevHash' $OUT)
[ $snph -ge 3 ] || { echo "FAIL: only $snph SetNewPrevHash (the payout change didn't replace the work at once)"; pass=0; }
grep -a -q "repayminer: Stratum V2 work now pays $NEW" $LOG || { echo "FAIL: no 'work now pays' log line"; pass=0; }
grep -a -q "repayminer: first share" $LOG || { echo "FAIL: no first-share log line"; pass=0; }
grep -v '^share' $OUT
[ $pass = 1 ] && echo "SV2 work replaced at once: PASS" || { echo "SV2 work replaced at once: FAIL"; exit 1; }
