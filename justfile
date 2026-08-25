CRATE := "tcup"
DEBUG_DIR := "target/debug/"
CAP := "cap_net_admin+ep"

[env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "sudo -E")]
test_tap:
    cargo test tap -- --no-capture --ignored

set_cap bin:
    sudo setcap {{ CAP }} {{ DEBUG_DIR }}{{ bin }}
