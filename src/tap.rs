#![allow(dead_code, unused_variables, unused_assignments)]

use crate::{error::Result, eth::EthFrame};
use std::{ffi::c_void, os::fd::OwnedFd, process::Command};

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
    pub fn new(name: &str) -> Result<Self> {
        tap_alloc(name)
    }

    pub fn write(&self, data: EthFrame) -> rustix::io::Result<usize> {
        rustix::io::write(&self.fd, &data.into_bytes())
    }

    pub fn read(&self, buf: &mut [u8]) -> rustix::io::Result<usize> {
        rustix::io::read(&self.fd, buf)
    }

    pub fn set_if_link(&self) -> Result<()> {
        println!("ip link set dev {} up", &self.name);
        let cmd = Command::new("ip")
            .args(["link", "set", "dev", &self.name, "up"])
            .output()
            .expect("failed to execute command");

        if !cmd.status.success() {
            let err = String::from_utf8(cmd.stderr).unwrap();
            return Err(crate::error::Error::Ip(err));
        }
        Ok(())
    }

    pub fn set_if_route(&self, route: &str) -> Result<()> {
        println!("ip route add {} dev {}", route, &self.name);
        let cmd = Command::new("ip")
            .args(["route", "add", route, "dev", &self.name])
            .output()
            .expect("failed to execute command");

        if !cmd.status.success() {
            let err = String::from_utf8(cmd.stderr).unwrap();
            return Err(crate::error::Error::Ip(err));
        }
        Ok(())
    }

    pub fn set_if_addr(&self, addr: &str) -> Result<()> {
        println!("ip addr add {} dev {} ", addr, &self.name);
        let cmd = Command::new("ip")
            .args(["addr", "add", "dev", &self.name, "local", addr])
            .output()
            .expect("failed to execute command");

        if !cmd.status.success() {
            let err = String::from_utf8(cmd.stderr).unwrap();
            return Err(crate::error::Error::Ip(err));
        }
        Ok(())
    }
}

#[repr(C)]
struct Ifreq {
    ifrname: [u8; IFNAMSIZ],
    ifreqdata: Ifreqdata,
}

unsafe impl Ioctl for &mut Ifreq {
    type Output = ();

    const IS_MUTATING: bool = true;

    fn opcode(&self) -> rustix::ioctl::Opcode {
        rustix::ioctl::opcode::write::<i32>(b'T', 202)
    }

    fn as_ptr(&mut self) -> *mut rustix::ffi::c_void {
        std::ptr::from_mut(*self) as *mut c_void
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
    hwaddr: libc::sockaddr,
    data: [u8; IFRQ_UNION_SIZE],
}

fn tap_alloc(name: &str) -> Result<TAPDevice> {
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

    unsafe { rustix::ioctl::ioctl(&fd, &mut ifreq)? };

    Ok(TAPDevice {
        name: name.to_string(),
        fd,
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        eth::{ETH_FRAME_MAX_SIZE, EthHeader},
        utils::setup_cap,
    };

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
    fn tap_ip() -> Result<()> {
        let name = "tap0";
        let route = "10.0.0.0/24";
        let addr = "10.0.0.5/24";

        setup_cap().unwrap();

        let tap = TAPDevice::new(name)?;
        tap.set_if_link()?;
        tap.set_if_route(route)?;
        // tap.set_if_addr(addr)?;

        loop {
            let mut buf = Box::new([0u8; ETH_FRAME_MAX_SIZE]);
            println!("listening...");
            let n = tap.read(&mut *buf).unwrap();
            println!("{n} bytes received");

            let hdr = EthHeader::from_bytes(&buf[..14].try_into().unwrap());
            println!("{hdr}");
        }
    }
}
