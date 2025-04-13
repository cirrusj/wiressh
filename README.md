# wiressh

`wiressh` is a simple SSH client that allows connectivity via **WireGuard** by using the [go userspace WireGuard](https://git.zx2c4.com/wireguard-go) implementation.

## Usage
```shell
./wiressh remote-server
```

```
Usage of wiressh:
	wiressh [flags] host
Flags:
  -c string
        wiressh config (default "~/.ssh/wiressh_config")
  -d    Debug
  -k string
        SSH known hosts (default "~/.ssh/known_hosts")
  -r string
        Record session to file (asciicast v2 format)
  -s string
        SSH config (default "~/.ssh/config")
```

## wiressh config
`wiressh` requires a config file (default: `~/.ssh/wiressh_config`) that contains entries similar to the ones defined in `ssh_config`. For example:
```
Host remote-server
  PrivateKey bm90IHJlYWxseSBhIHByaXZhdGVrZXk=
  PublicKey bm90IHJlYWxseSBhIHB1YmxpY2tleQ==
  PresharedKey bm90IHJlYWxseSBhIHByZXNoYXJlZGtleQ==
  IPAddress 10.0.0.2
  DNSServer 10.0.0.1
  WGServer 140.82.121.3:51820
  AllowedIP 0.0.0.0/0
```

[github.com/kevinburke/ssh_config](https://github.com/kevinburke/ssh_config) is used for parsing the `wiressh_config` file.

## ssh config
Currently wiressh does not allow you to specify SSH client settings (e.g. username, port, hostname, identityfile). As such, I recommend using the `~/.ssh/config` file for setting any of these options. The host should match the one in `wiressh_config`.
For example:
```
Host remote-server
  Port 9999
  User bob
  IdentityFile ~/.ssh/remote_server_key
  Hostname remote.server.local
```

A small number of `ssh_config` keywords are supported (`User`, `HostName`, `Port`, `IdentityFile`).

## Session Recording
You can record your SSH session in asciicast v2 format using the `-r` flag:

```shell
./wiressh -r session.cast remote-server
```

The recorded session can be played back using tools like [asciinema](https://asciinema.org/) or [asciinema-player](https://github.com/asciinema/asciinema-player).

## Known problems

- WireGuard and SSH connect timeouts are not working
- Port forwarding is not supported
- Debug (`-d`) will print the WireGuard private, public and preshared keys
- Not tested in various operating systems
- No tests
- I am not a developer and don't know Go :)

**Do not use for production workloads**

Feel free to open PRs
