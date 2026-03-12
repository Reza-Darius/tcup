#![allow(dead_code, unused_variables, unused_assignments)]

use std::{error::Error, ffi::c_void, os::fd::OwnedFd, process::Command};

use rustix::{
    fs::{Mode, OFlags},
    ioctl::Ioctl,
};

const IFF_TAP: i16 = 0x2;
const IFF_NO_PI: i16 = 0x1000;
const IFNAMSIZ: usize = 16; // including null terminator
// #define TUNSETIFF  _IOW('T', 202, int)
//
// pub const fn write<T>(group: u8, number: u8) -> Opcode
// _IOW(group, number, T)

#[derive(Debug)]
pub struct TAPDevice {
    name: String,
    fd: OwnedFd,
}

impl TAPDevice {
    pub fn new(name: &str) -> Result<Self, Box<dyn Error>> {
        tap_alloc(name)
    }

    pub fn write(&self, data: &[u8]) -> rustix::io::Result<usize> {
        rustix::io::write(&self.fd, data)
    }

    pub fn read(&self, buf: &mut [u8]) -> rustix::io::Result<usize> {
        rustix::io::read(&self.fd, buf)
    }

    fn set_if_link(&self) {
        println!("ip link set dev {} up", &self.name);
        let cmd = Command::new("sudo")
            .args(["ip", "link", "set", "dev", &self.name, "up"])
            .output()
            .expect("failed to execute command");

        if !cmd.status.success() {
            let err = String::from_utf8(cmd.stderr).unwrap();
            println!("{err}");
        }
    }

    fn set_if_route(&self, route: &str) {
        println!("ip route add dev {} {route}", &self.name);
        let cmd = Command::new("sudo")
            .args(["ip", "route", "add", "dev", &self.name, route])
            .output()
            .expect("failed to execute command");

        if !cmd.status.success() {
            let err = String::from_utf8(cmd.stderr).unwrap();
            println!("{err}");
        }
    }

    fn set_if_addr(&self, addr: &str) {
        println!("ip addr add dev {} local {addr}", &self.name);
        let cmd = Command::new("sudo")
            .args(["ip", "addr", "add", "dev", &self.name, "local", addr])
            .output()
            .expect("failed to execute command");

        if !cmd.status.success() {
            let err = String::from_utf8(cmd.stderr).unwrap();
            println!("{err}");
        }
    }
}

#[repr(C)]
struct Ifreq {
    ifrname: [u8; IFNAMSIZ],
    ifreqdata: Ifreqdata,
}

unsafe impl Ioctl for Ifreq {
    type Output = ();

    const IS_MUTATING: bool = true;

    fn opcode(&self) -> rustix::ioctl::Opcode {
        rustix::ioctl::opcode::write::<i32>(b'T', 202)
    }

    fn as_ptr(&mut self) -> *mut rustix::ffi::c_void {
        std::ptr::from_mut(self) as *mut c_void
    }

    unsafe fn output_from_ptr(
        out: rustix::ioctl::IoctlOutput,
        extract_output: *mut rustix::ffi::c_void,
    ) -> rustix::io::Result<Self::Output> {
        Ok(())
    }
}

const IFRQ_UNION_SIZE: usize = 24;

#[repr(C)]
union Ifreqdata {
    ifrflags: i16,
    data: [u8; IFRQ_UNION_SIZE],
}

fn tap_alloc(name: &str) -> Result<TAPDevice, Box<dyn Error>> {
    if name.len() > IFNAMSIZ - 1 {
        return Err("name is too large".into());
    };

    let fd = rustix::fs::open("/dev/net/tun", OFlags::RDWR, Mode::empty())?;

    let mut ifreq = Ifreq {
        ifrname: [0; _],
        ifreqdata: Ifreqdata {
            ifrflags: IFF_TAP | IFF_NO_PI,
        },
    };

    ifreq.ifrname[..name.len()].copy_from_slice(name.as_bytes());
    assert_eq!(ifreq.ifrname[name.len()], 0);

    let res = unsafe { rustix::ioctl::ioctl(&fd, ifreq) };
    res?;

    Ok(TAPDevice {
        name: name.to_string(),
        fd,
    })
}

pub fn mac(buf: &[u8; 6]) -> String {
    format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
    )
}

#[cfg(test)]
mod tests {
    use crate::eth::EthHeader;

    use super::*;
    use std::process::Command;

    #[test]
    fn calling_tun() {
        let name = "tcup_server";
        let res = tap_alloc(name).unwrap();

        let cmd = Command::new("ip")
            .arg("link")
            .output()
            .expect("failed to execute command");
        let output = String::from_utf8(cmd.stdout).unwrap();
        assert!(output.contains(name))
    }

    #[test]
    fn tap_send_recv() {
        let tap0 = TAPDevice::new("tap0").unwrap();
        let tap1 = TAPDevice::new("tap1").unwrap();

        // Minimal Ethernet frame (14-byte header + 1-byte payload)
        let mut frame = [0u8; 60];
        frame[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst MAC
        frame[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // EtherType
        frame[14] = 0x42; // payload

        tap0.write(&frame).unwrap();
        let mut buf = [0u8; 15];
        let n = tap1.read(&mut buf).unwrap();
        assert_eq!(n, 15);
        assert_eq!(&buf[..15], &frame[..15]);
    }

    #[test]
    fn tap_ip() {
        let name = "tap0";
        let route = "10.0.0.0/24";
        let addr = "10.0.0.5";

        let tap = TAPDevice::new(name).unwrap();
        tap.set_if_link();
        tap.set_if_route(route);
        tap.set_if_addr(addr);

        loop {
            let mut buf = [0u8; 1514];
            println!("listening...");
            let n = tap.read(&mut buf).unwrap();
            println!("{n} bytes received");

            let hdr = EthHeader::parse(&buf[..14].try_into().unwrap());
            println!("{hdr}");
        }
    }
}
