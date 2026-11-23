#!/bin/bash
# Stratum V2 end-to-end test stand on the private regtest chain:
#   regtest node (tools/regtest.sh) -> Solo45 Core with SV2 on :34260 -> reference Translator Proxy (tProxy) on :34261
# SV1 test miners talk to tProxy, tProxy talks Stratum V2 (encrypted) to Core.
#   bash tools/sv2_regtest.sh start | stop
# Needs the translator binary: cargo install translator_sv2 --version 0.7.0 --root ~/solo45-test/sv2bin --locked
T=$HOME/solo45-test/core-sv2
N=$HOME/solo45-test/regtest-node
TP=$HOME/solo45-test/sv2bin/bin/translator_sv2
mkdir -p $T
if [ "$1" = stop ]; then
  [ -f $T/tproxy.pid ] && kill $(cat $T/tproxy.pid) 2>/dev/null
  [ -f $T/pid ] && kill $(cat $T/pid) 2>/dev/null
  echo stopped; exit 0
fi
bash $(dirname $0)/regtest.sh start > /dev/null
ADDR=$(cat $HOME/solo45-test/core-regtest/address.txt)
for f in pool.log tproxy.log; do [ -f $T/$f ] && mv $T/$f $T/$f.old; done
SOLO45_STRATUM_PORT=3349 SOLO45_API_PORT=3389 SOLO45_SV2_PORT=34260 SOLO45_DATA_DIR=$T SOLO45_LOG_FILE=$T/pool.log \
SOLO45_START_DIFF=0.00001 SOLO45_MIN_DIFF=0.00001 SOLO45_DEFAULT_ADDRESS=$ADDR \
BITCOIN_RPC_URL=http://127.0.0.1:18543/ BITCOIN_RPC_COOKIE=$N/regtest/.cookie BITCOIN_ZMQ_HASHBLOCK=tcp://127.0.0.1:28544 \
setsid nohup $HOME/solo45-core/target/release/solo45-core serve > /dev/null 2>&1 < /dev/null &
echo $! > $T/pid
for i in $(seq 1 30); do [ -f $T/sv2-authority.json ] && grep -q 'Stratum V2 on' $T/pool.log 2>/dev/null && break; sleep 0.5; done
PUB=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public"])' $T/sv2-authority.json)
cat > $T/tproxy.toml <<CONF
downstream_address = "127.0.0.1"
downstream_port = 34261
max_supported_version = 2
min_supported_version = 2
downstream_extranonce2_size = 8
verify_payout = false
aggregate_channels = false
supported_extensions = []
log_file = "$T/tproxy.log"

[downstream_difficulty_config]
min_individual_miner_hashrate = 2000.0
shares_per_minute = 30.0
enable_vardiff = false
job_keepalive_interval_secs = 60

[[upstreams]]
address = "127.0.0.1"
port = 34260
authority_pubkey = "$PUB"
user_identity = "$ADDR.sv2proxy"
CONF
setsid nohup $TP -c $T/tproxy.toml > $T/tproxy.out 2>&1 < /dev/null &
echo $! > $T/tproxy.pid
# wait until tProxy listens for miners (a slow CI runner can need more than a few seconds), up to 30 s
for i in $(seq 1 60); do ss -ltn 2>/dev/null | grep -q '127.0.0.1:34261 ' && break; sleep 0.5; done
sleep 1
echo "core: $(grep -c . $T/pool.log) log lines; authority $PUB"
grep -a 'Stratum V2\|authorized' $T/pool.log | tail -n 3 | cut -c1-200
tail -n 5 $T/tproxy.out | cut -c1-200
