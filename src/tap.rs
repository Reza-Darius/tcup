#![allow(dead_code, unused_variables, unused_assignments)]

use crate::{error::Result, eth::EthFrame, types::Mac};
use std::{
    ffi::c_void,
    os::fd::{AsRawFd, OwnedFd},
    process::Command,
};

use rustix::{
    fs::{Mode, OFlags},
    ioctl::Ioctl,
};
use tokio::io::unix::AsyncFd;
use tracing::info;

const IFF_TAP: i16 = 0x2;
const IFF_NO_PI: i16 = 0x1000;
const IFNAMSIZ: usize = 16; // including null terminator

#[derive(Debug)]
pub struct TAPDevice {
    name: String,
    fd: AsyncFd<OwnedFd>,
}

impl TAPDevice {
    pub fn new(name: &str) -> Result<Self> {
        if name.len() > IFNAMSIZ - 1 {
            return Err("name is too large".into());
        };

        let fd = rustix::fs::open(
            "/dev/net/tun",
            OFlags::RDWR | OFlags::NONBLOCK,
            Mode::empty(),
        )?;

        let mut ifreq = Ifreq {
            ifrname: [0; _],
            ifreqdata: Ifreqdata {
                ifrflags: IFF_TAP | IFF_NO_PI,
            },
        };

        ifreq.ifrname[..name.len()].copy_from_slice(name.as_bytes());
        assert_eq!(ifreq.ifrname[name.len()], 0);

        unsafe { rustix::ioctl::ioctl(&fd, &mut ifreq)? };

        info!("tap initialized");

        Ok(TAPDevice {
            name: name.to_string(),
            fd: AsyncFd::new(fd)?,
        })
    }

    pub async fn write(&self, data: EthFrame) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;

            match guard.try_io(|inner| {
                rustix::io::write(inner.get_ref(), data.as_bytes()).map_err(Into::into)
            }) {
                Ok(res) => return Ok(res?),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;

            match guard
                .try_io(|inner| rustix::io::read(inner.get_ref(), &mut *buf).map_err(Into::into))
            {
                Ok(res) => return Ok(res?),
                Err(_would_block) => continue,
            }
        }
    }

    pub fn set_if_link(&self) -> Result<()> {
        let output = Command::new("ip")
            .args(["link", "set", "dev", &self.name, "up"])
            .output()
            .expect("failed to execute command");

        if !output.status.success() {
            let err = String::from_utf8(output.stderr).unwrap();
            return Err(crate::error::Error::Ip(err));
        }
        info!("ip link set dev {} up", &self.name);
        Ok(())
    }

    pub fn set_if_route(&self, route: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["route", "add", route, "dev", &self.name])
            .output()
            .expect("failed to execute command");

        if !output.status.success() {
            let err = String::from_utf8(output.stderr).unwrap();
            return Err(crate::error::Error::Ip(err));
        }
        info!("ip route add {} dev {}", route, &self.name);
        Ok(())
    }

    pub fn set_if_addr(&self, addr: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["addr", "add", "dev", &self.name, "local", addr])
            .output()
            .expect("failed to execute command");

        if !output.status.success() {
            let err = String::from_utf8(output.stderr).unwrap();
            return Err(crate::error::Error::Ip(err));
        }
        info!("ip addr add {} dev {} ", addr, &self.name);
        Ok(())
    }

    /// this needs to be called after settting the interface up otherwise the MAC address
    /// can get reassigned
    pub fn get_mac(&self) -> Result<Mac> {
        let name = &self.name;
        let fd = &self.fd;

        let mut ifreq = Ifreq {
            ifrname: [0; IFNAMSIZ],
            ifreqdata: Ifreqdata {
                data: [0; IFRQ_UNION_SIZE],
            },
        };
        ifreq.ifrname[..name.len()].copy_from_slice(name.as_bytes());

        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::SIOCGIFHWADDR, &mut ifreq) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let sa_data = unsafe { ifreq.ifreqdata.hwaddr.sa_data };
        let mac = Mac::from_octets([
            sa_data[0] as u8,
            sa_data[1] as u8,
            sa_data[2] as u8,
            sa_data[3] as u8,
            sa_data[4] as u8,
            sa_data[5] as u8,
        ]);
        info!("got MAC {mac}");
        Ok(mac)
    }
}

#[repr(C)]
struct Ifreq {
    ifrname: [u8; IFNAMSIZ],
    ifreqdata: Ifreqdata,
}

// #define TUNSETIFF  _IOW('T', 202, int)
//
// pub const fn write<T>(group: u8, number: u8) -> Opcode
// _IOW(group, number, T)

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
