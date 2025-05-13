# wiressh

`wiressh` is a simple SSH client that allows connectivity over multiple tunnel types, session recording, port forwarding, and live session sharing via web browser.

Supported tunnels are:
- **WireGuard** by using the [go userspace WireGuard](https://git.zx2c4.com/wireguard-go) implementation.
- **Tailscale** by using the [tsnet](https://tailscale.com/kb/1244/tsnet).
- **Direct** (no tunnel)

Features include:
- SSH over WireGuard, Tailscale or direct connection
- Session recording (asciicast v2)
- Port forwarding (LocalForward)
- Live sharing (read-only) of SSH sessions via web browser

## Usage
```shell
wiressh remote-server
```

```
wiressh - Simple SSH client with WireGuard and Tailscale tunnel support

Usage:
  wiressh [flags] host

Flags:
  -c string   Path to WireGuard configuration file (default "~/.ssh/wiressh_config")
  -d          Enable debug logging
  -l          Enable debug logging for the tunnel
  -t int      Connection timeout in seconds (default 15)
  -f          Print the configuration file format help
  -r string   Path to record file (asciicast v2 format)
  -s string   Enable live sharing on specified address (for example "127.0.0.1:9999")

Examples:
  wiressh myserver
  wiressh -r session.cast myserver
  wiressh -d -c ~/.ssh/custom_config myserver
  wiressh -s 127.0.0.1:9999 myserver

For more information, see: https://github.com/cirrusj/wiressh
```

## wiressh config
`wiressh` requires a config file (default: `~/.ssh/wiressh_config`) that contains entries similar to the ones defined in `ssh_config`. For example:
```
Host remote-server
  Type wireguard
  PrivateKey bm90IHJlYWxseSBhIHByaXZhdGVrZXk=
  PublicKey bm90IHJlYWxseSBhIHB1YmxpY2tleQ==
  PresharedKey bm90IHJlYWxseSBhIHByZXNoYXJlZGtleQ==
  IPAddress 10.0.0.2
  DNSServer 10.0.0.1
  WGServer 140.82.121.3:51820
  AllowedIP 0.0.0.0/0
  User root
  Hostname 10.10.10.10
  IdentityFile ~/.ssh/identity
  HostKey ecdsa-sha2-nistp256 bm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXk=

Host *.stage
  Type tailscale
  AuthKey tskey-auth-xxxxx
  IdentityFile ~/.ssh/identity-stage

Host www.stage
  User test
  HostKey ecdsa-sha2-nistp256 bm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXlfbm90X3JlYWxseV9hX2hvc3RrZXk=
```

The following keys are supported:
- Type: wireguard, tailscale or direct (required)
- Hostname: hostname of the server (will override the host argument if provided)
- User: username to connect as (optional, defaults to current user)
- Port: port to connect to (optional, defaults to 22)
- IdentityFile: path to the private key file (optional, defaults to ~/.ssh/id_rsa)
- HostKey: Remote server host key (optional, if not provided the remote server host key will be printed and the user will be asked if they want to continue)
- LocalForward: Configure an SSH LocalForward (optional, see `ssh_config` for more details)

For Wireguard (`Type: wireguard`):
- PrivateKey: WireGuard private key (required)
- PublicKey: WireGuard public key (required)
- PresharedKey: WireGuard preshared key (optional)
- AllowedIP: WireGuard allowed IP (optional, defaults to 0.0.0.0/0)
- WGServer: WireGuard server formatted as host:port (required)
- IPAddress: IP address to bind the WireGuard tunnel to (required)
- DNSServer: DNS server to use for the WireGuard tunnel (required)

For Tailscale (`Type: tailscale`):
-  AuthKey: Tailscale auth key (required)

[github.com/kevinburke/ssh_config](https://github.com/kevinburke/ssh_config) is used for parsing the `wiressh_config` file.

In a previous version, `wiressh` would also read values from `~/.ssh/config`. This has been removed in this version, opting for all values to be read from the `wiressh_config` file.

## Live Sharing (Read-Only)
You can share your SSH session in real-time (read-only) via a web browser by enabling the live sharing feature:

```shell
wiressh -s 127.0.0.1:9999 myserver
```

This starts a web server on `127.0.0.1:9999` by default. You (or others with access) can open a browser and view the SSH terminal session as it happens. This is a **read-only** feature—viewers cannot interact with the SSH session.

The live sharing feature uses [@xterm/xterm](https://xtermjs.org/) for the terminal display. The JS files are loaded from [jsDelivr](https://www.jsdelivr.com/) (Subresource Integrity hashes are used to verify the files).

---

## Session Recording
You can record your SSH session in [asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/) format using the `-r` flag:

```shell
wiressh -r session.cast remote-server
```

If the recording file already exist `wiressh` will exit without starting the session.

The recorded session can be played back using tools like [asciinema](https://asciinema.org/) or [asciinema-player](https://github.com/asciinema/asciinema-player).

## Tailscale
You need to create an ephemeral, pre-approved, reusable (or not if for a single use) key.

## Known problems
- Running multiple times:
  - Tailscale will work
  - Wireguard should work, as long as a different details are used for each host. Running with the same details, should cause the first `wiressh` instance to stop working
- tsnet seems to use MagicDNS names, and then net.Resolver for everything else (https://github.com/tailscale/tailscale/issues/4677)
- Not tested in various operating systems
- The live sharing feature does not support https. Do not use to share sensitive data
- I am not a developer and don't know Go :)

**Do not use on production systems**

Feel free to open PRs
