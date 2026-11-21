# Solo45 Core

**A fast solo Bitcoin mining pool in Rust, for your own node.** Test version.

Solo45 Core is the engine behind [Solo45](https://github.com/race45race/solo45), rewritten in Rust. It builds work
from your own Bitcoin node, puts your address in the coinbase and pays any block you find straight to you, with
no pool fee. It runs next to the Solo45 app, on its own port, so you can move miners over one at a time.

- **Same work as Solo45, byte for byte.** Jobs, coinbase, merkle branches and found blocks are cross-checked
  against Solo45's pool.
- **Fast block switching.** New blocks arrive by ZMQ the moment your node has them; miners get an empty job for
  the new height within a few milliseconds, then the full template.
- **Every job checked by your node** (`getblocktemplate` proposal mode).
- **Safe block submission.** A found block is saved to disk first, then sent, and resent up to 6 times if the
  node is down or still starting.
- **Steady share difficulty.** Vardiff per miner, remembered across restarts, or a fixed difficulty or share rate
  per miner.
- **Small.** One binary, about 2% of a CPU core and 40-160 MB of memory with full mainnet templates.

Planned: template policy and stall guard (from Solo45), then Stratum V2, job declaration, a proxy mode and public
stats pages.

## Install on Umbrel

1. Add the community app store `https://github.com/race45race/solo45` in umbrelOS (App Store → ⋯ → Community App
   Stores) and install **Solo45 Core**. It needs the **Bitcoin Node** app, fully synced.
2. Open Solo45 Core and enter your **payout address**. Your node checks it before it's saved.
3. Point a miner at **`stratum+tcp://<your Umbrel's IP>:3346`**. Keep a backup pool set on every miner.

Keep port 3346 on your home network: don't forward it to the internet.

## Run without Umbrel

```sh
docker run -d --name solo45-core -p 3346:3346 -v $PWD/data:/data \
  -e SOLO45_DATA_DIR=/data -e SOLO45_WEB_PORT=8346 \
  -e BITCOIN_RPC_URL=http://<node>:8332/ -e BITCOIN_RPC_USER=<user> -e BITCOIN_RPC_PASS=<pass> \
  -e BITCOIN_ZMQ_HASHBLOCK=tcp://<node>:28332 \
  ghcr.io/race45race/solo45-core:v0.0.3
```

The status page (port 8346) only answers the machine itself and the container's gateway; reach it through a
reverse proxy that checks a login, or an SSH tunnel.

## Settings

| Variable | Default | |
|---|---|---|
| `SOLO45_STRATUM_PORT` | 3346 | port for miners |
| `SOLO45_API_PORT` | 3386 | Solo45-compatible API (local or `X-Solo45-Token`) |
| `SOLO45_WEB_PORT` | 0 (off) | status page |
| `SOLO45_API_TOKEN` | | shared secret for the API |
| `SOLO45_DATA_DIR` | . | state.json, blocks_found.jsonl |
| `SOLO45_LOG_FILE` | stdout | log file, rotated at 20 MB |
| `BITCOIN_RPC_URL` | http://127.0.0.1:8332/ | |
| `BITCOIN_RPC_USER` / `_PASS` / `_COOKIE` | | node login (user/pass, or the cookie file) |
| `BITCOIN_ZMQ_HASHBLOCK` | | e.g. tcp://127.0.0.1:28332; without it Core polls every 100 ms |
| `SOLO45_DEFAULT_ADDRESS` | | payout address (or set it on the status page) |
| `SOLO45_SHARE_SECONDS` | 10 | vardiff target |
| `SOLO45_EMPTY_HOLD_S` | 10 | how long the empty job for a new block runs before the full template |
| `SOLO45_TEMPLATE_REFRESH_S` | 30 | new job with fresh transactions |

## Build

```sh
cargo test --release && cargo build --release
```

MIT license.
