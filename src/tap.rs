#![allow(dead_code, unused_variables, unused_assignments)]

use crate::error::Result;
use crate::eth::Mac;

use std::{
    ffi::OsStr,
    io,
    net::IpAddr,
    os::fd::{AsRawFd, OwnedFd, RawFd},
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::TryStreamExt;
use rtnetlink::{Handle, LinkUnspec, new_connection};
use rustix::fs::{Mode, OFlags};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, unix::AsyncFd};
use tracing::{Level, span, trace};
use udev::MonitorSocket;

#[derive(Debug)]
pub struct TAPDevice {
    name: String,
    addr: Option<(IpAddr, u8)>,
    mac: Mac,
    fd: AsyncFd<OwnedFd>,
}

#[derive(Debug, Default)]
pub struct TAPDeviceOptions {
    pub addr: Option<(IpAddr, u8)>,
}

impl TAPDevice {
    /// creates a new TAP network device, requires elevated privleges
    ///
    /// name can only be maximum 15 bytes long and should only contain ascii character
    ///
    /// can optionally be given an address and subnet
    pub async fn new(name: impl Into<String>, opts: TAPDeviceOptions) -> Result<Self> {
        let name = name.into();
        let _span = span!(Level::TRACE, "tap init", name = name).entered();

        if !name.is_ascii() {
            return Err(format!("provided name includes non ascii character").into());
        }

        if name.len() > libc::IFNAMSIZ - 1 {
            return Err(format!(
                "tapdevice init error: name is too long, got {}, max {}",
                name.len(),
                libc::IFNAMSIZ - 1
            )
            .into());
        };

        // we monitor udev devices to retrieve a stable MAC address later
        // the socket needs to be set up before opening the tap device!
        let monitor_sock = udev_sock()?;

        let tap = open_tap(&name)?;

        // set up tap device
        let (con, handler, _) = new_connection()?;
        tokio::spawn(con);

        // does the order matter?
        if let Some((addr, prefix)) = opts.addr {
            if prefix > 32 {
                return Err(format!("tapdevice init error: invalid prefix, needs to be between 0 and 32, got {prefix}").into());
            }
            if_add_addr(&handler, name.clone(), addr, prefix).await?;

            trace!("set ip addr");
        }

        if_link_up(&handler, name.clone()).await?;
        trace!("tap device brought up");

        // wait for stable MAC address
        await_udev(monitor_sock, &name).await?;
        let mac = request_mac(tap.as_raw_fd(), name.as_bytes())?;
        trace!(mac = %mac,"received mac");

        Ok(TAPDevice {
            name,
            addr: opts.addr,
            mac,
            fd: AsyncFd::new(tap)?,
        })
    }

    #[inline(always)]
    pub fn mac(&self) -> Mac {
        self.mac
    }

    #[inline(always)]
    pub fn dev_name(&self) -> &str {
        &self.name
    }

    #[inline(always)]
    pub fn addr(&self) -> Option<IpAddr> {
        self.addr.map(|(addr, _)| addr)
    }

    #[inline(always)]
    pub fn subnet(&self) -> Option<u8> {
        self.addr.map(|(_, sub)| sub)
    }
}

/// opens a new tap device in RW and non-blocking mode
fn open_tap(name: impl AsRef<[u8]>) -> Result<OwnedFd> {
    let fd = rustix::fs::open(
        "/dev/net/tun",
        OFlags::RDWR | OFlags::NONBLOCK,
        Mode::from_bits(0o666).unwrap(),
    )?;

    unsafe {
        let mut ifreq = new_ifreq(name);
        ifreq.ifr_ifru.ifru_flags = libc::IFF_TAP as i16 | libc::IFF_NO_PI as i16;

        if libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut ifreq) < 0 {
            return Err(std::io::Error::last_os_error().into());
        };
    }

    trace!("opened tap device");
    Ok(fd)
}

/// get a new udev socket to monitor device changes
fn udev_sock() -> Result<MonitorSocket> {
    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("net")?
        .listen()?;

    trace!("set up udev sock");
    Ok(socket)
}

async fn await_udev(socket: MonitorSocket, name: impl AsRef<OsStr>) -> Result<()> {
    trace!("awating udev");

    // prep a closure to iterate over the events
    let get_events = |socket: &MonitorSocket| -> io::Result<()> {
        while let Some(event) = socket.iter().next() {
            trace!(event_type = %event.event_type());
            trace!(sys_name = %event.sysname().display());
            trace!(sys_path = %event.syspath().display());
            trace!(dev_type = ?event.devtype());

            if event.sysname() == name.as_ref() {
                trace!("found device");
                return Ok(());
            }
        }
        io::Result::Err(io::Error::new(io::ErrorKind::NotFound, "device not found"))
    };

    // wrap the socket into the tokio machinery to poll it
    let async_fd = AsyncFd::new(socket)?;
    loop {
        let mut guard = async_fd.readable().await?;

        match guard.try_io(|inner| get_events(inner.get_ref())) {
            Ok(Ok(_)) => {
                trace!("found device");
                return Ok(());
            }

            // TODO: this might not be ideal
            Ok(Err(e)) => break,

            Err(_would_block) => {
                continue;
            }
        }
    }
    Err("could not find device".to_string().into())
}

fn request_mac(fd: RawFd, name: impl AsRef<[u8]>) -> Result<Mac> {
    let name = name.as_ref();
    let sa_data: libc::sockaddr;

    unsafe {
        let mut ifreq = new_ifreq(name);

        if libc::ioctl(fd, libc::SIOCGIFHWADDR, &mut ifreq) < 0 {
            return Err(std::io::Error::last_os_error().into());
        };
        sa_data = ifreq.ifr_ifru.ifru_hwaddr;
    }

    Ok(Mac::from_octets([
        sa_data.sa_data[0] as u8,
        sa_data.sa_data[1] as u8,
        sa_data.sa_data[2] as u8,
        sa_data.sa_data[3] as u8,
        sa_data.sa_data[4] as u8,
        sa_data.sa_data[5] as u8,
    ]))
}

/// construct an ifreq strcut with a name and all other fields zeroed
fn new_ifreq(name: impl AsRef<[u8]>) -> libc::ifreq {
    unsafe {
        let name = name.as_ref();
        // SAFETY: all zeroes is valid for ifreq
        let mut ifreq: libc::ifreq = std::mem::zeroed();

        ifreq.ifr_name[..name.len()].copy_from_slice(std::slice::from_raw_parts(
            name.as_ptr() as *const i8,
            name.len(),
        ));
        ifreq
    }
}

/// brings the tap device online
async fn if_link_up(handle: &Handle, if_name: impl AsRef<str>) -> Result<()> {
    handle
        .link()
        .set(LinkUnspec::new_with_name(if_name.as_ref()).up().build())
        .execute()
        .await
        .map_err(Into::into)
}

/// attempts to give the interface an address and subnet
async fn if_add_addr(
    handle: &Handle,
    if_name: impl Into<String>,
    addr: IpAddr,
    prefix_len: u8,
) -> Result<()> {
    let mut links = handle.link().get().match_name(if_name).execute();
    let link = links
        .try_next()
        .await?
        .ok_or("couldnt add addr to interface".to_string())?;

    handle
        .address()
        .add(link.header.index, addr, prefix_len)
        .execute()
        .await
        .map_err(Into::into)
}

impl AsyncRead for TAPDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard
                .try_io(|inner| rustix::io::read(inner.get_ref(), unfilled).map_err(Into::into))
            {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TAPDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;

            match guard.try_io(|inner| rustix::io::write(inner.get_ref(), buf).map_err(Into::into))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    #[inline(always)]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // tcp flush is a no-op
        Poll::Ready(Ok(()))
    }

    #[inline(always)]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // its a tap device, there is no thing to shut down
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use futures::StreamExt;
    use rtnetlink::packet_route::{address::AddressAttribute, link::LinkAttribute};

    use super::*;

    #[ignore = "this test required elevated privileges"]
    #[tokio::test]
    async fn tap() {
        let name = "tcup0";
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
        let subnet = 8;

        let tap = TAPDevice::new(
            name,
            TAPDeviceOptions {
                addr: Some((addr, subnet)),
            },
        )
        .await
        .unwrap();

        // println!("mac address: {}", tap.mac());
        // println!("ip address: {}", tap.addr().unwrap());

        let (con, handle, _) = new_connection().unwrap();
        tokio::spawn(con);

        let mut link_addr = handle.address().get().set_address_filter(addr).execute();
        let link_addr = link_addr.next().await.unwrap().unwrap();

        assert!(link_addr.attributes.iter().any(|attr| {
            if let AddressAttribute::Address(a) = attr
                && *a == addr
            {
                true
            } else {
                false
            }
        }));

        let mut links = handle.link().get().match_name(name).execute();
        let links = links.next().await.unwrap().unwrap();

        assert!(links.attributes.iter().any(|attr| {
            if let LinkAttribute::Address(mac) = attr
                && mac.as_slice() == tap.mac().octets()
            {
                true
            } else {
                false
            }
        }));
    }
}
