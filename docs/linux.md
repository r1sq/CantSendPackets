# Linux

On Linux there's `cspcheck`, the same checks without a window. It prints JSON, and runs as a
speed test endpoint that the Windows app finds like any other copy. A window for Linux may follow.

Download `cspcheck-linux-amd64` (or `-arm64`, for a Raspberry Pi) from the
[latest release](https://github.com/r1sq/CantSendPackets/releases/latest). It's one static file
that runs on any distribution.

    chmod +x cspcheck-linux-amd64
    ./cspcheck-linux-amd64                 # connectivity, loop and DHCP checks
    ./cspcheck-linux-amd64 -checks loop    # one check
    ./cspcheck-linux-amd64 -serve 24h      # be a speed test endpoint for a day

## Permissions

Linux reserves what the deeper checks need. Without it they degrade and say why, rather than
report a false all-clear.

| | As a normal user | With root or the capabilities |
|---|---|---|
| Ping | Only if `net.ipv4.ping_group_range` includes your group (most desktop distributions); otherwise the ping targets are left out | Always |
| Loop check | Broadcast rate from the kernel's counters | Also probes and repeated frames, as with Npcap on Windows |
| DHCP check | Can't run: port 68 is reserved | Works, from `0.0.0.0` like a real client |
| Everything else | Works | Works |

Either run it with `sudo`, or give the file the two capabilities once:

    sudo setcap cap_net_raw,cap_net_bind_service+ep cspcheck-linux-amd64

## A permanent speed test endpoint

A server or a Raspberry Pi that's always on gives every Windows copy something to test against.
As a systemd service:

    [Unit]
    Description=CantSendPackets speed test endpoint
    After=network-online.target
    Wants=network-online.target

    [Service]
    ExecStart=/usr/local/bin/cspcheck -serve 8760h
    DynamicUser=yes
    Restart=always

    [Install]
    WantedBy=multi-user.target

It needs no privileges for this. Open UDP and TCP 47116 in the firewall, and see
[Speed test](speed-test.md) for who can start a test.

## Differences from Windows

- **Proxies** come from `http_proxy`, `https_proxy` and `no_proxy`. PAC files and WPAD aren't
  evaluated, and a proxy login can only be typed, not taken from your account.
- **Broadcast counters** are the kernel's IP-level totals for all interfaces, so ARP isn't counted.
  Every loop also multiplies IP broadcasts, so it still shows.
- **The DHCP server** of the current lease is read from systemd-networkd, NetworkManager or
  dhclient, whichever manages the interface.
