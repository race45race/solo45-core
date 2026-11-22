#!/bin/bash
# Stratum V2 and a payout address change (stand: bash tools/sv2_regtest.sh start).
# A standard-channel test miner without an address in its name (it pays the pool's payout address) mines one share
# (a block on regtest) and pauses; meanwhile the payout address changes. Two runs:
#  A) a normal miner takes the new job (it becomes the active one at once): its next block pays the NEW address;
#  B) a miner that keeps mining its older job (SOLO45_TEST_STICKY=1): its share is still accepted, and being a block
#     it is still submitted, paying the OLD address, as on V1. (A payout change must not refuse a real block found
#     in the moment of the change; only a job the node refused is dropped at once, see test_sv2_refused.py.)
# Puts the old payout address back after each run.
set -u
B=$HOME/solo45-test/bitcoin-32.1/bin/bitcoin-cli
N="-regtest -datadir=$HOME/solo45-test/regtest-node -rpcport=18543"
ADDR=$(cat $HOME/solo45-test/core-regtest/address.txt)
CORE=$HOME/solo45-core/target/release/solo45-core
LOG=$HOME/solo45-test/core-sv2/pool.log
spk() { $B $N getaddressinfo $1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["scriptPubKey"])'; }
payout() { curl -s -X POST -H 'Content-Type: application/json' -d "{\"address\":\"$1\"}" 127.0.0.1:3389/api/payout > /dev/null; }
pays() { $B $N getblock $($B $N getblockhash $1) 2 | python3 -c 'import json,sys
b = json.load(sys.stdin); print(any(o["scriptPubKey"]["hex"] == sys.argv[1] for o in b["tx"][0]["vout"]))' "$2"; }
PUB=$(python3 -c 'import json,os; print(json.load(open(os.path.expanduser("~/solo45-test/core-sv2/sv2-authority.json")))["public"])')
pass=1
run() {  # $1 = label, $2 = sticky (0/1), $3 = which address block 2 must pay (old/new)
  local NEW=$($B $N -rpcwallet=core-test getnewaddress repay bech32)
  local H0=$($B $N getblockcount)
  local OUT=$HOME/solo45-test/core-sv2/repay-miner-$1.out
  SOLO45_TEST_STICKY=$2 timeout 120 $CORE sv2-miner 127.0.0.1:34260 $PUB "repayminer$1" 2 6 > $OUT &
  local M=$!
  for i in $(seq 1 60); do [ $($B $N getblockcount) -gt $H0 ] && break; sleep 0.5; done
  sleep 1
  payout $NEW
  wait $M
  payout $ADDR
  local H1=$($B $N getblockcount)
  [ $((H1 - H0)) -eq 2 ] || { echo "FAIL $1: height $H0 -> $H1 (expected +2)"; pass=0; return; }
  [ "$(pays $((H0 + 1)) $(spk $ADDR))" = True ] || { echo "FAIL $1: block 1 doesn't pay the old address"; pass=0; }
  if [ "$3" = new ]; then
    [ "$(pays $((H0 + 2)) $(spk $NEW))" = True ] || { echo "FAIL $1: block 2 doesn't pay the new address"; pass=0; }
  else
    [ "$(pays $((H0 + 2)) $(spk $ADDR))" = True ] || { echo "FAIL $1: block 2 (on the older job) doesn't pay the old address"; pass=0; }
  fi
  grep -a -q "repayminer$1: Stratum V2 work now pays $NEW" $LOG || { echo "FAIL $1: no 'work now pays' log line"; pass=0; }
  grep -q 'SubmitSharesError' $OUT && { echo "FAIL $1: a share was refused"; grep SubmitSharesError $OUT; pass=0; }
  echo "run $1 (sticky=$2): blocks $((H0 + 1))-$H1, block 2 pays the $3 address"
}
run A 0 new
run B 1 old
[ $pass = 1 ] && echo "SV2 payout change: PASS" || { echo "SV2 payout change: FAIL"; exit 1; }
