<div align="center">
<img src="images/tcup.png" width="400"/>
</div>

# tcup

Tcup is an asynchronous virtual networking interface capable of handling TCP/IP traffic

## Overview
- uses linux TAP devices to create a virtual interface
- handles Ethernet Frames (RFC 1042) and ARP (RFC 826)
- handles ICMP echoes (RFC 792)
- handles TCP (RFC 793)
- coming soon: socket API

## Getting Started (coming soon)

build with cargo
```
cargo install tcup
```

run with elevated permissions and run it with an ip and subnet

```
sudo setcap cap_net_admin=ep /usr/bin/tcup
tcup 10.0.0.4/24
```

open a port with your language of choice and enjoy some reliable packets!
