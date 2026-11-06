#!/usr/bin/env bash

# a script to setup iptables such that the connect.rs program can run properly
# us with arg "up" to apply and "down" to revert

# Check whether the script is running as root.
# $EUID = effective user ID (0 means root).
# -ne = "not equal".
if [[ $EUID -ne 0 ]]; then
    # exec replaces the current process with the new command.
    # sudo reruns the script with root privileges.
    # $0 contains the script's invocation path.
    # "$@" expands to all positional arguments, preserving spaces
    # and argument boundaries.
    exec sudo "$0" "$@"
fi

# case compares the first positional argument ($1) against patterns.
case "$1" in
    up)
        # Enable IPv4 packet forwarding.
        sysctl -w net.ipv4.ip_forward=1

        # Masquerade outgoing traffic from the 10.0.1.0/24 subnet.
        # ! -o tcup0 means "not leaving through tcup0".
        iptables -t nat -A POSTROUTING -s 10.0.1.0/24 ! -o tcup0 -j MASQUERADE

        # Allow forwarded traffic entering through tcup0.
        iptables -I FORWARD -i tcup0 -j ACCEPT

        # Allow return traffic for established connections.
        iptables -I FORWARD -o tcup0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        ;;

    down)
        sysctl -w net.ipv4.ip_forward=0

        # -D deletes the matching iptables rule.
        iptables -t nat -D POSTROUTING -s 10.0.1.0/24 ! -o tcup0 -j MASQUERADE
        iptables -D FORWARD -i tcup0 -j ACCEPT
        iptables -D FORWARD -o tcup0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        ;;

    *)
        # * matches anything not matched by the previous patterns.
        # >&2 redirects stderr (file descriptor 2).
        echo "Usage: $0 {up|down}" >&2
        exit 1
        ;;
esac
