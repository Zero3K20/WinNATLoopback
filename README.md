# WinNATLoopback – Split-Horizon DNS Server

A Windows GUI application that implements **Split-Horizon DNS** using a lightweight
local DNS server written in C++.  Instead of manipulating the network routing table
(NAT loopback), it resolves selected hostnames directly to private LAN IP addresses
so that clients inside the building reach internal services without going through the
firewall/public IP.

---

## Features

| Feature | Details |
|---|---|
| **Split-Horizon DNS** | Resolve configured hostnames to private IPs; forward everything else upstream |
| **Local DNS Records / DNS Rewrites** | Add/remove hostname → IP mappings via a simple GUI |
| **Upstream DNS forwarding** | All non-local queries are forwarded to a user-specified DNS server (e.g. `8.8.8.8`) |
| **Persistent configuration** | Records and upstream DNS setting are saved to `dns_config.ini` next to the executable |
| **Activity log** | Live log pane shows which queries were answered locally vs. forwarded |

---

## Requirements

* **Windows 10 / Server 2016 or later** (uses Winsock2, `inet_pton`)
* **Visual Studio 2019** (platform toolset v142, Windows SDK 10.0)
* **Administrator rights** at runtime – binding UDP port 53 requires elevation
  (the application manifest already requests `requireAdministrator`)

---

## Building

1. Open `SplitHorizonDNS.sln` in Visual Studio 2019.
2. Select the desired configuration (`Debug|x64` recommended) and build.
3. The output binary lands in `SplitHorizonDNS\x64\Debug\SplitHorizonDNS.exe`
   (or the equivalent for your chosen platform/configuration).

---

## Running

> **Run as Administrator** – right-click the exe and choose *Run as administrator*,
> or launch from an elevated prompt.  Port 53 cannot be bound without elevation.

### Quick-start

1. In the **DNS Server** field enter your upstream DNS (default `8.8.8.8`).
2. Click **Add Record** for each local hostname you want to override:
   * **Hostname** – the fully-qualified or short hostname (e.g. `myserver.local`)
   * **IP Address** – the private LAN address to return (e.g. `192.168.1.50`)
   * **DNS Server** – the upstream DNS that handles all other queries
3. Click **Start Server**.
4. Point the client machine's DNS to the IP of the machine running this server
   (or set it in your DHCP server for the whole network).

### Pointing clients at the local DNS

* **Single machine (test):** `netsh interface ip set dns "Local Area Connection" static 127.0.0.1`
* **DHCP option 6** on your router/DHCP server: set the DNS server to the IP of
  the machine running SplitHorizonDNS.

---

## How it works

```
Client query: myserver.local ?
        │
        ▼
SplitHorizonDNS (UDP :53)
        │
        ├─ hostname in local records? ──YES──▶ reply with configured private IP
        │
        └─ NO ──▶ forward to upstream DNS (e.g. 8.8.8.8) ──▶ relay response
```

Records and the upstream DNS address are persisted in `dns_config.ini` (INI format)
in the same directory as the executable, so they survive restarts.
