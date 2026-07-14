# hbot

`hbot` is a small interactive Go tool for managing a personal `sing-box` server.

It is intentionally narrow:

- first-run setup for `sing-box`
- initialize `/etc/sing-box/config.json`
- enable/start the `sing-box` service when a service manager exists
- fallback to hbot-managed background mode when `systemctl` is unavailable
- try to enable BBR; failures are warnings
- add Shadowsocks and VLESS TCP Reality inbounds
- add HTTP exit outbounds
- route selected inbound nodes through selected exits
- export Clash `proxies` config
- show status, start, restart, and stop `sing-box`

The config format targets current `sing-box` 1.13.x.

## Build

```bash
go build -buildvcs=false -o hbot .
```

Build Linux/Ubuntu binaries from Windows:

```bat
build-linux.bat
```

It creates both `hbot-linux-amd64` and `hbot-linux-arm64`.

## Publish

Create a GitHub Release and upload only these assets:

```text
hbot-linux-amd64
hbot-linux-arm64
```

The installer script stays in the Git repository. Use jsDelivr first because `raw.githubusercontent.com` can return `429 Too Many Requests` on shared NAT IPs.

Install latest release:

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/ranhongfeixue/hbot@master/install-hbot.sh | sh
```

or:

```bash
wget -O - https://cdn.jsdelivr.net/gh/ranhongfeixue/hbot@master/install-hbot.sh | sh
```

Pin a specific release tag if needed:

```bash
wget -O - https://cdn.jsdelivr.net/gh/ranhongfeixue/hbot@master/install-hbot.sh | HBOT_BASE_URL=https://github.com/ranhongfeixue/hbot/releases/download/v1.0.0 sh
```

Raw GitHub fallback:

```bash
wget -O - https://raw.githubusercontent.com/ranhongfeixue/hbot/master/install-hbot.sh | sh
```

The installer downloads the right binary for `amd64` or `arm64`, installs it as `hbot` under a global `PATH` directory, and makes it executable. It prefers `/usr/local/bin`; if that is not in `PATH`, it uses `/usr/bin`.

Copy the binary to the server:

```bash
sudo install -m 0755 hbot-linux-amd64 /usr/local/bin/hbot
```

Use `hbot-linux-arm64` instead for ARM64 Ubuntu.

## Run

Run the tool without commands:

```bash
sudo hbot
```

On first run it checks whether `sing-box` exists. If missing, it asks whether to download and install `sing-box` 1.13.14 using the official installer.

It then initializes the server config if needed:

- asks for your server domain/IP
- creates `/etc/hbot/state.json`
- creates `/etc/sing-box/config.json` if missing
- tries to enable `sing-box` at boot when a supported boot manager exists
- starts `sing-box`
- tries to enable BBR

After setup, it opens the function menu:

```text
1) add
2) export
3) status
4) add exit
5) rules
6) restart
7) start
8) stop
0) exit
```

Command mode is intentionally disabled. Use `sudo hbot`, not `hbot add` or `hbot restart`.

If the server has no `systemctl`, hbot starts sing-box itself in the background:

- pid: `/etc/hbot/sing-box.pid`
- log: `/etc/hbot/sing-box.log`

This is useful for minimal Ubuntu/container-style environments where commands like `systemctl`, `apt`, `nano`, or `vim` are not available.

## Add

Choose `add`, then select:

- `ss`
- `vless-reality`

Name rules:

- required
- must start with an English letter
- may contain only English letters, numbers, `_`, and `-`

Shadowsocks defaults:

- method: `aes-256-gcm`
- network: TCP + UDP
- password: generated automatically

VLESS Reality defaults:

- SNI: `www.nvidia.com`
- UUID: generated automatically
- Reality private/public key pair: generated automatically
- short id: 8 random hex characters
- fingerprint: `chrome`

After a profile is added, hbot checks the generated sing-box config and restarts sing-box so the new inbound takes effect immediately.

## Status

Choose `status` to show:

- service state
- state and config paths
- initialized server
- profiles and their current exit
- configured outbounds
- inbound-to-exit rules

Profiles without an explicit rule use their own/direct server exit.

## Add Exit

Choose `add exit` to add an HTTP outbound.

The flow asks for:

- name
- HTTP server domain/IP
- port
- optional username and password

The generated sing-box outbound uses:

```json
{
  "type": "http",
  "tag": "http-proxy",
  "server": "proxy.example.com",
  "server_port": 8080
}
```

Adding an exit does not change any profile by itself.

## Rules

Choose `rules` to select which profiles should use an HTTP exit.

The flow asks for:

- exit: an HTTP exit, or `direct` to clear the rule
- profiles: all or selected numbers

hbot writes sing-box route rules in this shape:

```json
{
  "inbound": ["ss-tw"],
  "action": "route",
  "outbound": "http-proxy"
}
```

Only selected profiles get explicit rules. Profiles without rules keep the default direct/own exit.

## Export Clash

Choose `export`.

The export flow asks:

- which profiles to export: all or selected numbers

The Clash `server` field uses the domain/IP saved during first-run setup. The port comes from each saved profile.

Output goes to stdout as:

```yaml
proxies:
  - {name: "tw-iepl-1", server: "fde63gz6-1y61.apt-hcloud.com", port: 12046, type: "ss", cipher: "aes-256-gcm", password: "secret", udp: true}
  - {name: "neburst-jk-hk", type: "vless", server: "fde63gz6-1y61.apt-hcloud.com", port: 53790, uuid: "bdf18969-4589-4060-9627-82909a5505fe", cipher: "auto", tls: true, udp: false, network: "tcp", servername: "www.nvidia.com", "client-fingerprint": "chrome", "reality-opts": {"public-key": "SsN67VcBMJvXwp7lo9YjRxBRObbCW0J46Y_hBzU3ji0", "short-id": "9fa0"}}
```

## Random Values

All random values use Go `crypto/rand`.

- Shadowsocks password: 32 random bytes, base64url encoded. About 256 bits.
- VLESS UUID: UUID v4. About 122 random bits.
- Reality private key: generated X25519 key. The public key is derived from it and becomes the client `pbk`.
- Reality short id: 8 random hex characters. This is 32 bits, so there are 4,294,967,296 possible values.
- `spx`: 8 random bytes, base64url encoded, used as a generated path-like value in the share link.

For one personal server with a small number of profiles, collisions are effectively irrelevant.
