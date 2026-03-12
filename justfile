CRATE := "tcup"
TARGET_DIR := "target/debug/deps"
CAP := "cap_net_admin+ep"

build-tests:
    cargo test --no-run

find-test:
    ls {{ TARGET_DIR }}/{{ CRATE }}-* | grep -v '\.d$'

setcap: build-tests
    sudo setcap {{ CAP }} `just find-test`

test *args: clean_tap setcap
    # sudo `just find-test` --test {{ args }} --test-threads=1
    cargo test {{ args }}

test_send_recv *args: clean_tap
    just setup_tap_bridge
    cargo test{{ args }}

setup_tap_bridge:
    sudo ip tuntap add dev tap0 mode tap
    sudo ip tuntap add dev tap1 mode tap
    sudo ip link add name br0 type bridge
    sudo ip link set tap0 master br0
    sudo ip link set tap1 master br0
    sudo ip link set dev br0 up
    sudo ip link set dev tap0 up
    sudo ip link set dev tap1 up

clean_tap:
    sudo ip link delete tap0 || true
    sudo ip link delete tap1 || true
    sudo ip link delete br0 type bridge || true

test_iptap:
    sudo ip tuntap add dev tap0 mode tap
    sudo ip link set dev tap0 up
    sudo ip route add dev tap0 10.0.0.0/24
    sudo ip addr add dev tap0 local 10.0.0.5
    cargo test tap_ip

clean:
    cargo clean
