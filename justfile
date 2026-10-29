SERVER_BIN := "tcup"
DEBUG_DIR := "target/debug/"
CAP := "cap_net_admin+ep"

[env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "sudo -E")]
test_tap:
    cargo test tap -- --no-capture --ignored

set_cap bin:
    sudo setcap {{ CAP }} {{ DEBUG_DIR }}{{ bin }}

run: build cap
    cargo run --bin {{ SERVER_BIN }}

build:
    cargo build --bin {{ SERVER_BIN }}

cap:
    sudo setcap {{ CAP }} {{ DEBUG_DIR }}{{ SERVER_BIN }}
