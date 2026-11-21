#!/bin/bash
# Private regtest chain + Solo45 Core for the found-block test. Nothing here touches the mainnet node or Solo45.
#   bash tools/regtest.sh start   start the test node (and set it up the first time) and Core on 3348/3388
#   bash tools/regtest.sh stop    stop both
BIN=$HOME/solo45-test/bitcoin-32.1/bin
N=$HOME/solo45-test/regtest-node
C=$HOME/solo45-test/core-regtest
CLI="$BIN/bitcoin-cli -regtest -datadir=$N"
mkdir -p $N $C
if [ "$1" = stop ]; then
  [ -f $C/pid ] && kill $(cat $C/pid) 2>/dev/null
  $CLI stop 2>/dev/null
  echo stopped; exit 0
fi
cat > $N/bitcoin.conf <<CONF
regtest=1
[regtest]
rpcport=18543
port=18544
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
listen=0
connect=0
dnsseed=0
fallbackfee=0.0001
zmqpubhashblock=tcp://127.0.0.1:28544
CONF
$CLI getblockcount >/dev/null 2>&1 || $BIN/bitcoind -regtest -datadir=$N -daemon >/dev/null
for i in $(seq 1 30); do $CLI getblockcount >/dev/null 2>&1 && break; sleep 0.5; done
$CLI loadwallet core-test >/dev/null 2>&1 || $CLI createwallet core-test >/dev/null 2>&1
[ -f $C/address.txt ] || $CLI getnewaddress core-test bech32 > $C/address.txt
ADDR=$(cat $C/address.txt)
[ "$($CLI getblockcount)" -ge 101 ] || $CLI generatetoaddress 101 $ADDR >/dev/null
[ -f $C/token.txt ] || head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n' > $C/token.txt
[ -f $C/pid ] && kill -0 $(cat $C/pid) 2>/dev/null && { echo "Core already running"; exit 0; }
SOLO45_STRATUM_PORT=3348 SOLO45_API_PORT=3388 SOLO45_API_TOKEN=$(cat $C/token.txt) \
SOLO45_START_DIFF=0.00001 SOLO45_MIN_DIFF=0.00001 SOLO45_DEFAULT_ADDRESS=$ADDR SOLO45_DATA_DIR=$C \
BITCOIN_RPC_URL=http://127.0.0.1:18543/ BITCOIN_RPC_COOKIE=$N/regtest/.cookie BITCOIN_ZMQ_HASHBLOCK=tcp://127.0.0.1:28544 \
setsid nohup $HOME/solo45-core/target/release/solo45-core serve > $C/pool.log 2>&1 < /dev/null &
echo $! > $C/pid
sleep 2
echo "node height $($CLI getblockcount), payout $ADDR"
head -n 4 $C/pool.log
