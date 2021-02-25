use crate::cshadow as c;
use crate::host::descriptor::socket::Packet;
use crate::host::descriptor::{
    FileFlags, FileMode, FileStatus, NewStatusListenerFilter, StatusEventSource, SyncSendPointer,
    SyscallReturn,
};
use crate::utility::byte_queue::ByteQueue;
use crate::utility::event_queue::{EventQueue, Handle};

use log::*;

#[derive(Debug, PartialEq)]
enum UdpState {
    Closed,
    Established,
}

impl std::fmt::Display for UdpState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UdpState::Closed => write!(f, "Closed"),
            UdpState::Established => write!(f, "Established"),
        }
    }
}

struct PacketBuffer {
    buffer: std::collections::VecDeque<Packet>,
    len_bytes: usize,
    max_bytes: usize,
}

impl PacketBuffer {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            buffer: std::collections::VecDeque::new(),
            len_bytes: 0,
            max_bytes,
        }
    }

    pub fn add_packet(&mut self, packet: Packet) {
        self.len_bytes += packet.get_payload_len() as usize;
        self.buffer.push_back(packet);
    }

    pub fn remove_packet(&mut self) -> Option<Packet> {
        let packet = self.buffer.pop_front()?;
        self.len_bytes -= packet.get_payload_len() as usize;
        Some(packet)
    }

    pub fn peek_packet(&self) -> Option<&Packet> {
        if self.buffer.len() == 0 {
            None
        } else {
            Some(&self.buffer[0])
        }
    }

    pub fn len(&self) -> usize {
        self.len_bytes
    }

    pub fn has_space(&self) -> bool {
        self.len_bytes < self.max_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.len_bytes == 0
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn set_max_bytes(&mut self, max: usize) {
        self.max_bytes = max;
    }
}

pub struct InetDgramFile {
    event_source: StatusEventSource,
    family: nix::sys::socket::AddressFamily,
    state: UdpState,
    status: FileStatus,
    mode: FileMode,
    flags: FileFlags,
    buffer_event_handle: Option<Handle<(FileStatus, FileStatus)>>,
    send_buffer: PacketBuffer,
    recv_buffer: PacketBuffer,
    peer_addr: Option<nix::sys::socket::InetAddr>,
    bound_addr: Option<nix::sys::socket::InetAddr>,
}

impl InetDgramFile {
    pub fn new(
        family: nix::sys::socket::AddressFamily,
        mode: FileMode,
        flags: FileFlags,
        recv_buf_size: usize,
        send_buf_size: usize,
    ) -> Self {
        assert!(
            family == nix::sys::socket::AddressFamily::Inet
                || family == nix::sys::socket::AddressFamily::Inet6
        );

        let mut socket = Self {
            event_source: StatusEventSource::new(),
            family,
            state: UdpState::Closed,
            status: FileStatus::ACTIVE,
            mode,
            flags,
            buffer_event_handle: None,
            send_buffer: PacketBuffer::new(send_buf_size),
            recv_buffer: PacketBuffer::new(recv_buf_size),
            peer_addr: None,
            bound_addr: None,
        };

        socket
            .status
            .insert(socket.filter_status(FileStatus::WRITABLE));

        socket
    }

    pub fn get_flags(&self) -> FileFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: FileFlags) {
        self.flags = flags;
    }

    pub fn get_bound_address(&self) -> Option<nix::sys::socket::SockAddr> {
        self.bound_addr.map(|x| nix::sys::socket::SockAddr::Inet(x))
    }

    pub fn set_bound_address(&mut self, addr: nix::sys::socket::SockAddr) -> Result<(), String> {
        let addr = match addr {
            nix::sys::socket::SockAddr::Inet(addr) => match addr.port() {
                0 => return Err("Can't bind to an address with a port of 0".into()),
                _ => addr,
            },
            _ => return Err("Can't set a non-inet address for an inet socket".into()),
        };

        if self.bound_addr.is_none() {
            self.bound_addr = Some(addr);
            Ok(())
        } else {
            Err("Socket is already bound".into())
        }
    }

    pub fn get_peer_address(&self) -> Option<nix::sys::socket::SockAddr> {
        self.peer_addr.map(|x| nix::sys::socket::SockAddr::Inet(x))
    }

    pub fn get_protocol_version(&self) -> c::ProtocolType {
        c::_ProtocolType_PUDP
    }

    pub fn address_family(&self) -> nix::sys::socket::AddressFamily {
        self.family
    }

    pub fn connect(
        &mut self,
        //family: nix::sys::socket::AddressFamily,
        addr: Option<nix::sys::socket::SockAddr>,
        _event_queue: &mut EventQueue,
    ) -> SyscallReturn {
        let addr = match addr {
            Some(nix::sys::socket::SockAddr::Inet(addr)) => Some(addr),
            Some(_) => return SyscallReturn::Error(nix::errno::Errno::EINVAL),
            None => None,
        };

        self.peer_addr = addr;

        if addr.is_none() {
            // dissolve our existing defaults
            self.state = UdpState::Closed;
        } else {
            // set new defaults
            self.state = UdpState::Established;
        }

        /*
        if (family == nix::sys::socket::AddressFamily::Unspec) {
            // dissolve our existing defaults
            self.peer_addr = None;
            self.state = UdpState::Closed;
        } else {
            // set new defaults
            self.peer_addr = Some(addr);
            self.state = UdpState::Established;
        }
        */

        SyscallReturn::Success(0)
    }

    pub fn shutdown(&self, how: nix::sys::socket::Shutdown) -> SyscallReturn {
        if self.state == UdpState::Closed {
            SyscallReturn::Error(nix::errno::Errno::ENOTCONN)
        } else {
            SyscallReturn::Success(0)
        }
    }

    pub fn getsockopt(
        &self,
        sys: &mut c::SysCallHandler,
        level: libc::c_int,
        optname: libc::c_int,
        optval_ptr: c::PluginPtr,
        optval_len: &mut libc::socklen_t,
    ) -> SyscallReturn {
        fn writeopt<T: Copy>(
            sys: &mut c::SysCallHandler,
            value: &T,
            optval_ptr: c::PluginPtr,
            optval_len: &mut libc::socklen_t,
        ) {
            let len_to_copy = std::cmp::min(*optval_len as usize, std::mem::size_of::<T>());

            let optval_ptr = unsafe {
                c::process_getWriteablePtr(sys.process, sys.thread, optval_ptr, len_to_copy as u64)
            };

            unsafe {
                std::ptr::copy_nonoverlapping(
                    value as *const _ as *const u8,
                    optval_ptr as *mut u8,
                    len_to_copy,
                )
            };

            *optval_len = len_to_copy as libc::socklen_t;
        }

        match level {
            libc::SOL_SOCKET => match optname {
                libc::SO_SNDBUF => {
                    let val = self.send_buffer.max_bytes() as libc::c_int;
                    writeopt::<libc::c_int>(sys, &val, optval_ptr, optval_len);
                    warn!("Wrote value of {}", val);
                    SyscallReturn::Success(0)
                }
                libc::SO_RCVBUF => {
                    let val = self.recv_buffer.max_bytes() as libc::c_int;
                    writeopt::<libc::c_int>(sys, &val, optval_ptr, optval_len);
                    warn!("Wrote value of {}", val);
                    SyscallReturn::Success(0)
                }
                libc::SO_ERROR => {
                    writeopt::<libc::c_int>(sys, &(0 as libc::c_int), optval_ptr, optval_len);
                    SyscallReturn::Success(0)
                }
                _ => {
                    warn!(
                        "getsockopt on level SOL_SOCKET called with unsupported option {}",
                        optname,
                    );
                    SyscallReturn::Error(nix::errno::Errno::ENOPROTOOPT)
                }
            },
            libc::SOL_TCP => SyscallReturn::Error(nix::errno::Errno::EOPNOTSUPP),
            _ => SyscallReturn::Error(nix::errno::Errno::ENOPROTOOPT),
        }
    }

    pub fn setsockopt(
        &mut self,
        sys: &mut c::SysCallHandler,
        level: libc::c_int,
        optname: libc::c_int,
        optval_ptr: c::PluginPtr,
        optval_len: libc::socklen_t,
    ) -> SyscallReturn {
        fn readopt<T: Copy>(
            sys: &mut c::SysCallHandler,
            optval_ptr: c::PluginPtr,
            optval_len: libc::socklen_t,
        ) -> Result<T, SyscallReturn> {
            let len = std::mem::size_of::<T>();

            if (optval_len as usize) < len {
                return Err(SyscallReturn::Error(nix::errno::Errno::EINVAL));
            }

            let optval_ptr = unsafe {
                c::process_getReadablePtr(sys.process, sys.thread, optval_ptr, len as u64)
            } as *const T;

            Ok(unsafe { *optval_ptr })
        }

        match level {
            libc::SOL_SOCKET => match optname {
                libc::SO_SNDBUF => {
                    let value = match readopt::<libc::c_int>(sys, optval_ptr, optval_len) {
                        Ok(x) => x,
                        Err(x) => return x,
                    };

                    let new_size = (value as i64) * 2;

                    // Linux also has limits SOCK_MIN_SNDBUF (slightly greater than 4096) and the sysctl max
                    // limit. We choose a reasonable lower limit for Shadow. The minimum limit in man 7
                    // socket is incorrect.
                    let new_size = std::cmp::max(new_size, 4096);

                    // This upper limit was added as an arbitrarily high number so that we don't change
                    // Shadow's behaviour, but also prevents an application from setting this to something
                    // unnecessarily large like INT_MAX.
                    let new_size = std::cmp::min(new_size, 268435456); // 2^28 = 256 MiB

                    self.send_buffer.set_max_bytes(new_size as usize);
                    SyscallReturn::Success(0)
                }
                libc::SO_RCVBUF => {
                    let value = match readopt::<libc::c_int>(sys, optval_ptr, optval_len) {
                        Ok(x) => x,
                        Err(x) => return x,
                    };

                    let new_size = (value as i64) * 2;

                    // Linux also has limits SOCK_MIN_RCVBUF (slightly greater than 2048) and the sysctl max
                    // limit. We choose a reasonable lower limit for Shadow. The minimum limit in man 7
                    // socket is incorrect.
                    let new_size = std::cmp::max(new_size, 2048);

                    // This upper limit was added as an arbitrarily high number so that we don't change
                    // Shadow's behaviour, but also prevents an application from setting this to something
                    // unnecessarily large like INT_MAX.
                    let new_size = std::cmp::min(new_size, 268435456); // 2^28 = 256 MiB

                    self.recv_buffer.set_max_bytes(new_size as usize);
                    SyscallReturn::Success(0)
                }
                libc::SO_REUSEADDR => {
                    warn!("setsockopt SO_REUSEADDR not yet implemented");
                    SyscallReturn::Success(0)
                }
                libc::SO_REUSEPORT => {
                    warn!("setsockopt SO_REUSEPORT not yet implemented");
                    SyscallReturn::Success(0)
                }
                libc::SO_KEEPALIVE => {
                    // TODO: implement this, libevent uses it in evconnlistener_new_bind()
                    warn!("setsockopt SO_KEEPALIVE not yet implemented");
                    SyscallReturn::Success(0)
                }
                _ => {
                    warn!(
                        "setsockopt on level SOL_SOCKET called with unsupported option {}",
                        optname,
                    );
                    SyscallReturn::Error(nix::errno::Errno::ENOPROTOOPT)
                }
            },
            _ => SyscallReturn::Error(nix::errno::Errno::ENOPROTOOPT),
        }
    }

    pub fn add_packet(&mut self, mut packet: Packet, event_queue: &mut EventQueue) {
        packet.add_delivery_status(c::_PacketDeliveryStatusFlags_PDS_RCV_SOCKET_PROCESSED);

        self.recv_buffer.add_packet(packet);

        debug!("Added a packet to the socket's recv buffer");

        self.adjust_status(
            FileStatus::READABLE,
            self.recv_buffer.len() > 0,
            event_queue,
        );
    }

    pub fn remove_packet(&mut self, event_queue: &mut EventQueue) -> Option<Packet> {
        let rv = self.send_buffer.remove_packet();

        if rv.is_some() {
            debug!("Removed a packet from the socket's send buffer");
        } else {
            debug!(
                "Attempted to remove a packet from the socket's send buffer, but none available"
            );
        }

        self.adjust_status(
            FileStatus::WRITABLE,
            self.send_buffer.has_space(),
            event_queue,
        );

        rv
    }

    pub fn peek_next_packet(&self) -> Option<&Packet> {
        self.send_buffer.peek_packet()
    }

    pub fn recvfrom(
        &mut self,
        bytes: Option<&mut [u8]>,
        event_queue: &mut EventQueue,
    ) -> (Option<nix::sys::socket::SockAddr>, SyscallReturn) {
        let packet = self.recv_buffer.remove_packet();

        if packet.is_some() {
            debug!("Removed a packet from the socket's recv buffer");
        } else {
            debug!(
                "Attempted to remove a packet from the socket's recv buffer, but none available"
            );
        }

        let rv = if let Some(mut packet) = packet {
            if let Some(bytes) = bytes {
                // copy lesser of requested and available amount to application buffer
                let packet_len = packet.get_payload_len();
                let copy_len = std::cmp::min(bytes.len(), packet_len as usize);
                assert_eq!(copy_len, packet.copy_payload(0, bytes) as usize);

                packet.add_delivery_status(c::_PacketDeliveryStatusFlags_PDS_RCV_SOCKET_DELIVERED);

                let from_addr = nix::sys::socket::SockAddr::Inet(
                    nix::sys::socket::InetAddr::from_std(&packet.get_source()),
                );
                (Some(from_addr), SyscallReturn::Success(copy_len as i32))
            } else {
                (None, SyscallReturn::Error(nix::errno::Errno::EFAULT))
            }
        } else {
            (None, SyscallReturn::Error(nix::errno::EWOULDBLOCK))
        };

        self.adjust_status(
            FileStatus::READABLE,
            self.recv_buffer.len() > 0,
            event_queue,
        );

        rv
    }

    pub fn sendto(
        &mut self,
        bytes: Option<&[u8]>,
        addr: Option<nix::sys::socket::SockAddr>,
        event_queue: &mut EventQueue,
    ) -> SyscallReturn {
        let addr = match addr {
            Some(addr) => match addr {
                nix::sys::socket::SockAddr::Inet(addr) => addr,
                _ => {
                    info!("Not an inet address");
                    return SyscallReturn::Error(nix::errno::Errno::EINVAL);
                }
            },
            None => match self.peer_addr {
                Some(addr) => addr,
                None => {
                    info!("No address provided, and no peer address");
                    return SyscallReturn::Error(nix::errno::Errno::EDESTADDRREQ);
                }
            },
        };

        let bytes = match bytes {
            Some(x) => x,
            None => {
                info!("Cannot send a null buffer");
                return SyscallReturn::Error(nix::errno::Errno::EFAULT);
            }
        };

        if bytes.len() > c::CONFIG_DATAGRAM_MAX_SIZE as usize {
            return SyscallReturn::Error(nix::errno::Errno::EMSGSIZE);
        }

        let host = unsafe { c::worker_getActiveHost() };
        let host_id = unsafe { c::host_getID(host) };
        let packet_id = unsafe { c::host_getNewPacketID(host) };

        let mut packet = Packet::from_bytes(bytes, host_id, packet_id);
        packet.set_udp(
            c::ProtocolUDPFlags_PUDP_NONE,
            self.bound_addr.unwrap().to_std(),
            addr.to_std(),
        );
        packet.add_delivery_status(c::_PacketDeliveryStatusFlags_PDS_SND_CREATED);

        self.send_buffer.add_packet(packet);

        debug!("Added a packet to the socket's send buffer");

        self.adjust_status(
            FileStatus::WRITABLE,
            self.send_buffer.has_space(),
            event_queue,
        );

        SyscallReturn::Success(bytes.len() as i32)
    }

    pub fn close(&mut self, event_queue: &mut EventQueue) -> SyscallReturn {
        // TODO: do we want to do anything here?
        SyscallReturn::Success(0)
    }

    pub fn add_listener(
        &mut self,
        monitoring: FileStatus,
        filter: NewStatusListenerFilter,
        notify_fn: impl Fn(FileStatus, FileStatus, &mut EventQueue) + Send + Sync + 'static,
    ) -> Handle<(FileStatus, FileStatus)> {
        self.event_source
            .add_listener(monitoring, filter, notify_fn)
    }

    pub fn add_legacy_listener(&mut self, ptr: *mut c::StatusListener) {
        self.event_source.add_legacy_listener(ptr);
    }

    pub fn remove_legacy_listener(&mut self, ptr: *mut c::StatusListener) {
        self.event_source.remove_legacy_listener(ptr);
    }

    pub fn status(&self) -> FileStatus {
        self.status
    }

    fn filter_status(&self, mut status: FileStatus) -> FileStatus {
        // if not open for reading, remove the readable flag
        if !self.mode.contains(FileMode::READ) {
            status.remove(FileStatus::READABLE);
        }

        // if not open for writing, remove the writable flag
        if !self.mode.contains(FileMode::WRITE) {
            status.remove(FileStatus::WRITABLE);
        }

        status
    }

    fn adjust_status(
        &mut self,
        status: FileStatus,
        do_set_bits: bool,
        event_queue: &mut EventQueue,
    ) {
        let old_status = self.status;

        // remove any flags that aren't relevant
        let status = self.filter_status(status);

        // add or remove the flags
        self.status.set(status, do_set_bits);

        self.handle_status_change(old_status, event_queue);
    }

    fn handle_status_change(&mut self, old_status: FileStatus, event_queue: &mut EventQueue) {
        let statuses_changed = self.status ^ old_status;

        // if nothing changed
        if statuses_changed.is_empty() {
            return;
        }

        self.event_source
            .notify_listeners(self.status, statuses_changed, event_queue);
    }
}
