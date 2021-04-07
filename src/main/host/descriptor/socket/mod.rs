use atomic_refcell::AtomicRefCell;
use std::sync::Arc;

use crate::cshadow as c;
use crate::host::descriptor::{
    FileFlags, FileMode, FileStatus, NewStatusListenerFilter, StatusEventSource, SyncSendPointer,
    SyscallReturn,
};
use crate::utility::event_queue::{EventQueue, Handle};

use log::*;

pub mod inet;

#[derive(Clone)]
pub enum SocketFile {
    InetDgram(Arc<AtomicRefCell<inet::InetDgramFile>>),
}

impl SocketFile {
    pub fn borrow(&self) -> SocketFileRef {
        match self {
            Self::InetDgram(ref f) => SocketFileRef::InetDgram(f.borrow()),
        }
    }

    pub fn borrow_mut(&self) -> SocketFileRefMut {
        match self {
            Self::InetDgram(ref f) => SocketFileRefMut::InetDgram(f.borrow_mut()),
        }
    }

    pub fn canonical_handle(&self) -> usize {
        match self {
            Self::InetDgram(f) => Arc::as_ptr(f) as usize,
        }
    }
}

pub enum SocketFileRef<'a> {
    InetDgram(atomic_refcell::AtomicRef<'a, inet::InetDgramFile>),
}

pub enum SocketFileRefMut<'a> {
    InetDgram(atomic_refcell::AtomicRefMut<'a, inet::InetDgramFile>),
}

impl_many!(SocketFileRefMut<'_>, SocketFileRef<'_> {
    enum_passthrough!(self, (), InetDgram;
        pub fn status(&self) -> FileStatus
    );
    enum_passthrough!(self, (), InetDgram;
        pub fn get_flags(&self) -> FileFlags
    );
    enum_passthrough!(self, (), InetDgram;
        pub fn get_bound_address(&self) -> Option<nix::sys::socket::SockAddr>
    );
    enum_passthrough!(self, (), InetDgram;
        pub fn get_peer_address(&self) -> Option<nix::sys::socket::SockAddr>
    );
    enum_passthrough!(self, (sys, level, optname, optval_ptr, optval_len), InetDgram;
        pub fn getsockopt(
            &self,
            sys: &mut c::SysCallHandler,
            level: libc::c_int,
            optname: libc::c_int,
            optval_ptr: c::PluginPtr,
            optval_len: &mut libc::socklen_t,
        ) -> SyscallReturn
    );
    enum_passthrough!(self, (), InetDgram;
        pub fn get_protocol_version(&self) -> c::ProtocolType
    );
    enum_passthrough!(self, (), InetDgram;
        pub fn address_family(&self) -> nix::sys::socket::AddressFamily
    );
    enum_passthrough!(self, (), InetDgram;
        pub fn peek_next_packet(&self) -> Option<&Packet>
    );
});

impl SocketFileRefMut<'_> {
    enum_passthrough!(self, (bytes, event_queue), InetDgram;
        pub fn recvfrom(
            &mut self,
            bytes: Option<&mut [u8]>,
            event_queue: &mut EventQueue,
        ) -> (Option<nix::sys::socket::SockAddr>, SyscallReturn)
    );
    enum_passthrough!(self, (bytes, addr, event_queue), InetDgram;
        pub fn sendto(
            &mut self,
            bytes: Option<&[u8]>,
            addr: Option<nix::sys::socket::SockAddr>,
            event_queue: &mut EventQueue,
        ) -> SyscallReturn
    );
    enum_passthrough!(self, (event_queue), InetDgram;
        pub fn close(&mut self, event_queue: &mut EventQueue) -> SyscallReturn
    );
    enum_passthrough!(self, (flags), InetDgram;
        pub fn set_flags(&mut self, flags: FileFlags)
    );
    enum_passthrough!(self, (addr), InetDgram;
        pub fn set_bound_address(&mut self, addr: nix::sys::socket::SockAddr) -> Result<(), String>
    );
    enum_passthrough!(self, (addr, event_queue), InetDgram;
        pub fn connect(
            &mut self,
            addr: Option<nix::sys::socket::SockAddr>,
            event_queue: &mut EventQueue,
        ) -> SyscallReturn
    );
    enum_passthrough!(self, (how), InetDgram;
        pub fn shutdown(&mut self, how: nix::sys::socket::Shutdown) -> SyscallReturn
    );
    enum_passthrough!(self, (sys, level, optname, optval_ptr, optval_len), InetDgram;
        pub fn setsockopt(
            &mut self,
            sys: &mut c::SysCallHandler,
            level: libc::c_int,
            optname: libc::c_int,
            optval_ptr: c::PluginPtr,
            optval_len: libc::socklen_t,
        ) -> SyscallReturn
    );
    enum_passthrough!(self, (packet, event_queue), InetDgram;
        pub fn add_packet(&mut self, packet: Packet, event_queue: &mut EventQueue)
    );
    enum_passthrough!(self, (event_queue), InetDgram;
        pub fn remove_packet(&mut self, event_queue: &mut EventQueue) -> Option<Packet>
    );
    enum_passthrough!(self, (ptr), InetDgram;
        pub fn add_legacy_listener(&mut self, ptr: *mut c::StatusListener)
    );
    enum_passthrough!(self, (ptr), InetDgram;
        pub fn remove_legacy_listener(&mut self, ptr: *mut c::StatusListener)
    );
}

pub struct Packet {
    pointer: SyncSendPointer<c::Packet>,
}

impl Packet {
    pub fn from_ptr(pointer: *mut c::Packet) -> Self {
        unsafe { c::packet_ref(pointer) };
        Self {
            pointer: SyncSendPointer(pointer),
        }
    }

    pub fn from_bytes(buffer: &[u8], host_id: libc::c_uint, packet_id: u64) -> Self {
        Self {
            pointer: SyncSendPointer(unsafe {
                c::packet_new(
                    buffer.as_ptr() as *const libc::c_void,
                    buffer.len() as libc::c_ulong,
                    host_id,
                    packet_id,
                )
            }),
        }
    }

    pub fn as_ptr(&self) -> *const c::Packet {
        self.pointer.ptr()
    }

    pub fn into_ptr(self) -> *mut c::Packet {
        // ref the packet since dropping will unref the packet
        unsafe { c::packet_ref(self.pointer.ptr()) };
        self.pointer.ptr()
    }

    pub fn set_udp(
        &mut self,
        udp_flag: libc::c_uint,
        src_addr: std::net::SocketAddr,
        dest_addr: std::net::SocketAddr,
    ) {
        let (src_ip, src_port) = if let std::net::SocketAddr::V4(addr) = src_addr {
            (*addr.ip(), addr.port())
        } else {
            unimplemented!();
        };

        let (dest_ip, dest_port) = if let std::net::SocketAddr::V4(addr) = dest_addr {
            (*addr.ip(), addr.port())
        } else {
            unimplemented!();
        };

        debug!("set udp src: {}, dest: {}", src_addr, dest_addr);

        assert_ne!(u32::from_be_bytes(src_ip.octets()).to_be(), 0);
        assert_ne!(src_port.to_be(), 0);
        assert_ne!(u32::from_be_bytes(dest_ip.octets()).to_be(), 0);
        assert_ne!(dest_port.to_be(), 0);

        unsafe {
            c::packet_setUDP(
                self.pointer.ptr(),
                udp_flag,
                u32::from_be_bytes(src_ip.octets()).to_be(),
                src_port.to_be(),
                u32::from_be_bytes(dest_ip.octets()).to_be(),
                dest_port.to_be(),
            )
        };
    }

    pub fn add_delivery_status(&mut self, status: c::PacketDeliveryStatusFlags) {
        unsafe { c::packet_addDeliveryStatus(self.pointer.ptr(), status) };
    }

    pub fn get_payload_len(&self) -> libc::c_uint {
        unsafe { c::packet_getPayloadLength(self.pointer.ptr()) }
    }

    pub fn copy_payload(&self, payload_offset: libc::c_ulong, buf: &mut [u8]) -> libc::c_uint {
        unsafe {
            c::packet_copyPayload(
                self.pointer.ptr(),
                0,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::c_ulong,
            )
        }
    }

    pub fn get_source(&self) -> std::net::SocketAddr {
        let ip = unsafe { c::packet_getSourceIP(self.pointer.ptr()) };
        let port = unsafe { c::packet_getSourcePort(self.pointer.ptr()) };

        let ip = u32::from_be(ip).to_be_bytes();
        let ip = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);

        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(ip, u16::from_be(port)))
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        // unref the packet object
        unsafe { c::packet_unref(self.pointer.ptr()) };
    }
}

mod export {
    use super::*;

    /// Decrement the ref count of the posix file object. The pointer must not be used after
    /// calling this function.
    #[no_mangle]
    pub extern "C" fn socketfile_drop(file: *const SocketFile) {
        assert!(!file.is_null());

        unsafe { Box::from_raw(file as *mut SocketFile) };
    }

    #[no_mangle]
    pub extern "C" fn socketfile_cloneRef(file: *const SocketFile) -> *const SocketFile {
        assert!(!file.is_null());

        let socket = unsafe { &*file };
        Box::into_raw(Box::new(socket.clone()))
    }

    #[no_mangle]
    pub extern "C" fn socketfile_getProtocol(socket: *const SocketFile) -> c::ProtocolType {
        assert!(!socket.is_null());

        let socket = unsafe { &*socket };
        socket.borrow().get_protocol_version()
    }

    #[no_mangle]
    pub extern "C" fn socketfile_getPeerName(
        socket: *const SocketFile,
        ip_ptr: *mut libc::in_addr_t,
        port_ptr: *mut libc::in_port_t,
    ) -> bool {
        assert!(!socket.is_null());

        let socket = unsafe { &*socket };

        let address = socket.borrow().get_peer_address();

        if let Some(address) = address {
            let address = match address {
                nix::sys::socket::SockAddr::Inet(x) => x,
                _ => {
                    error!("Cannot get an inet address for a non-inet socket");
                    unreachable!();
                }
            };

            let ip = match address.ip() {
                nix::sys::socket::IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()),
                _ => unreachable!(),
            };

            if !ip_ptr.is_null() {
                unsafe { *ip_ptr = ip.to_be() };
            }

            if !port_ptr.is_null() {
                unsafe { *port_ptr = address.port().to_be() };
            }

            true
        } else {
            false
        }
    }

    #[no_mangle]
    pub extern "C" fn socketfile_getSocketName(
        socket: *const SocketFile,
        ip_ptr: *mut libc::in_addr_t,
        port_ptr: *mut libc::in_port_t,
    ) -> bool {
        assert!(!socket.is_null());

        let socket = unsafe { &*socket };

        let address = socket.borrow().get_bound_address();

        if let Some(address) = address {
            let address = match address {
                nix::sys::socket::SockAddr::Inet(x) => x,
                _ => {
                    error!("Cannot get an inet address for a non-inet socket");
                    unreachable!();
                }
            };

            let ip = match address.ip() {
                nix::sys::socket::IpAddr::V4(ip) => u32::from_be_bytes(ip.octets()),
                _ => unreachable!(),
            };

            if !ip_ptr.is_null() {
                unsafe { *ip_ptr = ip.to_be() };
            }

            if !port_ptr.is_null() {
                unsafe { *port_ptr = address.port().to_be() };
            }

            true
        } else {
            false
        }
    }

    #[no_mangle]
    pub extern "C" fn socketfile_peekNextOutPacket(socket: *const SocketFile) -> *const c::Packet {
        assert!(!socket.is_null());

        let socket = unsafe { &*socket };

        match socket.borrow().peek_next_packet() {
            Some(packet) => packet.as_ptr(),
            None => std::ptr::null(),
        }
    }

    #[no_mangle]
    pub extern "C" fn socketfile_pushInPacket(socket: *const SocketFile, packet: *mut c::Packet) {
        assert!(!socket.is_null());
        assert!(!packet.is_null());

        let socket = unsafe { &*socket };
        let packet = Packet::from_ptr(packet);

        EventQueue::queue_and_run(|event_queue| {
            socket.borrow_mut().add_packet(packet, event_queue);
        })
    }

    #[no_mangle]
    pub extern "C" fn socketfile_pullOutPacket(socket: *const SocketFile) -> *mut c::Packet {
        assert!(!socket.is_null());

        let socket = unsafe { &*socket };

        let packet =
            EventQueue::queue_and_run(|event_queue| socket.borrow_mut().remove_packet(event_queue));

        match packet {
            Some(packet) => packet.into_ptr(),
            None => std::ptr::null_mut(),
        }
    }
}
