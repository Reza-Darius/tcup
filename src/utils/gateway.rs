use std::net::Ipv4Addr;

pub fn get_default_gateway() -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        // destination == 00000000 means default route
        if fields[1] == "00000000" {
            let gw = u32::from_str_radix(fields[2], 16).ok()?;
            // value is in little-endian hex
            return Some(Ipv4Addr::from(u32::from_le(gw)));
        }
    }
    None
}
