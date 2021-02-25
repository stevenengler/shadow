use crate::cshadow as c;
use crate::host::descriptor::socket;
use crate::host::descriptor::{
    CompatDescriptor, Descriptor, DescriptorFlags, FileFlags, FileMode, FileStatus, PosixFile,
    SyscallReturn,
};
use crate::host::syscall;
use crate::host::syscall::Trigger;
use crate::utility::event_queue::EventQueue;

use std::sync::Arc;

use atomic_refcell::AtomicRefCell;
use log::*;

pub fn socket(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let domain = unsafe { args.args[0].as_i64 } as libc::c_int;
    let socket_type = unsafe { args.args[1].as_i64 } as libc::c_int;
    let protocol = unsafe { args.args[2].as_i64 } as libc::c_int;

    socket_helper(sys, args, domain, socket_type, protocol)
}

pub fn socket_helper(
    sys: &mut c::SysCallHandler,
    args: &c::SysCallArgs,
    domain: libc::c_int,
    socket_type: libc::c_int,
    protocol: libc::c_int,
) -> c::SysCallReturn {
    // remove any flags from the socket type
    let flags = socket_type & (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC);
    let socket_type = socket_type & !flags;

    // if it's not an inet datagram socket, use the C syscall handler instead
    if domain != libc::AF_INET || socket_type != libc::SOCK_DGRAM {
        return unsafe {
            c::syscallhandler_socket(sys as *mut c::SysCallHandler, args as *const c::SysCallArgs)
        };
    }

    let mut file_flags = FileFlags::empty();
    let mut descriptor_flags = DescriptorFlags::empty();

    if flags & libc::SOCK_NONBLOCK != 0 {
        file_flags.insert(FileFlags::NONBLOCK);
    }

    if flags & libc::SOCK_CLOEXEC != 0 {
        descriptor_flags.insert(DescriptorFlags::CLOEXEC);
    }

    let mut desc = match domain {
        libc::AF_INET => match socket_type {
            libc::SOCK_DGRAM => {
                let protocol = if protocol == 0 {
                    libc::IPPROTO_UDP
                } else {
                    protocol
                };

                if protocol != libc::IPPROTO_UDP {
                    return SyscallReturn::Error(nix::errno::Errno::EPROTONOSUPPORT).into();
                }

                let socket = socket::inet::InetDgramFile::new(
                    nix::sys::socket::AddressFamily::from_i32(domain).unwrap(),
                    FileMode::READ | FileMode::WRITE,
                    file_flags,
                    unsafe { c::host_getConfiguredRecvBufSize(sys.host) } as usize,
                    unsafe { c::host_getConfiguredSendBufSize(sys.host) } as usize,
                );
                let socket = Arc::new(AtomicRefCell::new(socket));

                Descriptor::new(PosixFile::Socket(socket::SocketFile::InetDgram(socket)))
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    };

    desc.set_flags(descriptor_flags);

    let fd = unsafe {
        c::process_registerCompatDescriptor(
            sys.process,
            Box::into_raw(Box::new(CompatDescriptor::New(desc))),
        )
    };

    debug!("Created socket fd {}", fd);

    SyscallReturn::Success(fd).into()
}

fn get_addr_family(addr: *const libc::sockaddr, size: usize) -> Result<libc::sa_family_t, String> {
    if size < std::mem::size_of::<libc::sockaddr>() {
        return Err("Address not long enough".into());
    }

    Ok(unsafe { &*addr }.sa_family)
}

fn sockaddr_to_nix(
    addr: *const libc::sockaddr,
    size: usize,
) -> Result<nix::sys::socket::SockAddr, String> {
    let family = get_addr_family(addr, size)? as libc::c_int;

    match family {
        libc::AF_INET => {
            if size != std::mem::size_of::<libc::sockaddr_in>() {
                return Err("Incompatible size for sockaddr_in".into());
            }

            let addr = unsafe { &*(addr as *const libc::sockaddr_in) };
            Ok(nix::sys::socket::SockAddr::Inet(
                nix::sys::socket::InetAddr::V4(*addr),
            ))
        }
        libc::AF_INET6 => {
            if size != std::mem::size_of::<libc::sockaddr_in6>() {
                return Err("Incompatible size for sockaddr_in6".into());
            }

            let addr = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Ok(nix::sys::socket::SockAddr::Inet(
                nix::sys::socket::InetAddr::V6(*addr),
            ))
        }
        libc::AF_UNIX => {
            let path_offset = {
                // need a temporary object to find the offset since rust doesn't have an offsetof()
                let temp_sockaddr = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
                &temp_sockaddr.sun_path as *const _ as usize - &temp_sockaddr as *const _ as usize
            };

            if size > std::mem::size_of::<libc::sockaddr_un>() || size < path_offset {
                return Err("Incompatible size for sockaddr_un".into());
            }

            let addr = unsafe { &*(addr as *const libc::sockaddr_un) };
            // assume the path is the last member of the sockaddr_un
            let path_len = size - path_offset;
            Ok(nix::sys::socket::SockAddr::Unix(
                nix::sys::socket::UnixAddr(*addr, path_len),
            ))
        }
        _ => Err("Unexpected address family".into()),
    }
}

fn empty_sockaddr(family: libc::sa_family_t) -> Result<nix::sys::socket::SockAddr, String> {
    match family as libc::c_int {
        libc::AF_INET => {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            Ok(nix::sys::socket::SockAddr::Inet(
                nix::sys::socket::InetAddr::V4(addr),
            ))
        }
        libc::AF_INET6 => {
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            Ok(nix::sys::socket::SockAddr::Inet(
                nix::sys::socket::InetAddr::V6(addr),
            ))
        }
        libc::AF_UNIX => {
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            Ok(nix::sys::socket::SockAddr::Unix(
                nix::sys::socket::UnixAddr(addr, 0),
            ))
        }
        _ => Err("Unexpected address family".into()),
    }
}

pub fn bind(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[1].as_ptr };
    let addr_len = unsafe { args.args[2].as_u64 } as libc::socklen_t;

    debug!("Trying to bind socket fd {}", fd);

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_bind(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => {
            return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into();
        }
    };

    //
    //
    //
    //
    //
    //

    // it's an error if the socket is already bound
    if socket.borrow().get_bound_address().is_some() {
        info!("socket descriptor {} is already bound to an address", fd);
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // TODO: we assume AF_INET here, change this when we support AF_UNIX
    // let unix_len = std::mem::size_of::<libc::sockaddr_un>(); // if sa_family==AF_UNIX
    let inet_len = std::mem::size_of::<libc::sockaddr_in>();
    if (addr_len as usize) < inet_len {
        info!("supplied address is not large enough for a inet address");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // make sure the addr PluginPtr is not NULL
    if addr_ptr.val == 0 {
        info!("binding to a NULL address is invalid");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    let addr_ptr =
        unsafe { c::process_getReadablePtr(sys.process, sys.thread, addr_ptr, addr_len as u64) };
    let addr_ptr = addr_ptr as *const libc::sockaddr;

    let addr = sockaddr_to_nix(addr_ptr, addr_len as usize);

    let addr = match addr {
        Ok(x) => x,
        Err(x) => {
            warn!("Unable to convert the sockaddr: {}", x);
            return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
        }
    };

    // TODO: we assume AF_INET here, change this when we support AF_UNIX
    if !matches!(
        addr,
        nix::sys::socket::SockAddr::Inet(nix::sys::socket::InetAddr::V4(_))
    ) {
        warn!("we only support AF_INET",);
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    let (bind_ip_be, bind_port_be) = match addr {
        nix::sys::socket::SockAddr::Inet(addr) => {
            let ip = match addr.ip() {
                nix::sys::socket::IpAddr::V4(x) => u32::from_be_bytes(x.octets()).to_be(),
                _ => unreachable!(),
            };
            (ip, addr.port().to_be())
        }
        _ => unreachable!(),
    };

    // get the requested address and port
    //struct sockaddr_in* inet_addr = (struct sockaddr_in*)addr;
    //in_addr_t bindAddr = inet_addr->sin_addr.s_addr;
    //in_port_t bindPort = inet_addr->sin_port;

    //
    //
    //
    //
    //
    //

    // make sure we have an interface at that address
    if unsafe { c::host_doesInterfaceExist(sys.host, bind_ip_be) } == 0 {
        info!(
            "no network interface exists for the provided bind address {}",
            addr
        );
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // each protocol type gets its own ephemeral port mapping
    //let protocol_type = unsafe { c::socket_getProtocol(socket_desc) };
    let protocol_type = socket.borrow().get_protocol_version();

    // get a free ephemeral port if they didn't specify one
    let mut bind_port_be = bind_port_be;
    if bind_port_be == 0 {
        bind_port_be =
            unsafe { c::host_getRandomFreePort(sys.host, protocol_type, bind_ip_be, 0, 0) };
        debug!(
            "binding to generated ephemeral port {}",
            u16::from_be(bind_port_be)
        ); // ntohs(bind_port)
    }
    let bind_port_be = bind_port_be;

    let addr = match addr {
        nix::sys::socket::SockAddr::Inet(addr) => {
            let new_addr = nix::sys::socket::InetAddr::new(addr.ip(), u16::from_be(bind_port_be));
            nix::sys::socket::SockAddr::Inet(new_addr)
        }
        _ => unreachable!(),
    };

    // ephemeral port unavailable
    if (bind_port_be == 0) {
        info!("binding required an ephemeral port and none are available");
        return SyscallReturn::Error(nix::errno::Errno::EADDRINUSE).into();
    }

    // make sure the port is available at this address for this protocol
    if unsafe {
        c::host_isInterfaceAvailable(sys.host, protocol_type, bind_ip_be, bind_port_be, 0, 0)
    } == 0
    {
        info!("the provided address {} is not available", addr,);
        return SyscallReturn::Error(nix::errno::Errno::EADDRINUSE).into();
    }

    //
    //
    //
    //
    //
    //

    //socket_setPeerName(socket, peerAddress, peerPort);
    //socket_setSocketName(socket, bindAddress, bindPort);

    socket.borrow_mut().set_bound_address(addr).unwrap();

    // set associations
    //let socket_ptr = Box::into_raw(Box::new(socket.clone()));
    //unsafe { c::host_associateInterfaceSocketFile(sys.host, socket_ptr, bind_ip_be) };
    unsafe { c::host_associateInterfaceSocketFile(sys.host, socket as *const _, bind_ip_be) };

    //
    //
    //
    //
    //
    //

    SyscallReturn::Success(0).into()
}

pub fn recvfrom(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let buf_ptr = unsafe { args.args[1].as_ptr };
    let buf_len = unsafe { args.args[2].as_u64 } as libc::size_t;
    let flags = unsafe { args.args[3].as_u64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[4].as_ptr };
    let addr_len_ptr = unsafe { args.args[5].as_ptr };

    recvfrom_helper(
        sys,
        args,
        fd,
        buf_ptr,
        buf_len,
        flags,
        addr_ptr,
        addr_len_ptr,
    )
}

pub fn recvfrom_helper(
    sys: &mut c::SysCallHandler,
    args: &c::SysCallArgs,
    fd: libc::c_int,
    buf_ptr: c::PluginPtr,
    buf_len: libc::size_t,
    flags: libc::c_int,
    addr_ptr: c::PluginPtr,
    addr_len_ptr: c::PluginPtr,
) -> c::SysCallReturn {
    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_recvfrom(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let posix_file = desc.get_file();
    let file_flags = posix_file.borrow().get_flags();

    let socket = match posix_file {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    /*
    // if the buffer is null, the len must be 0
    if buf_ptr.val == 0 && buf_len != 0 {
        info!("When receiving with a null buffer, the len must be 0");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }
    */

    // address length pointer cannot be null if the address buffer is non-null
    if addr_ptr.val != 0 && addr_len_ptr.val == 0 {
        info!("When receiving with a null addr, the addr len must also be null");
        return SyscallReturn::Error(nix::errno::Errno::EFAULT).into();
    }

    let mut buf = if buf_ptr.val != 0 {
        if buf_len > 0 {
            // TODO: dynamically compute size based on how much data is actually available in the descriptor
            let size_needed = match socket {
                // we should not truncate datagram messages
                socket::SocketFile::InetDgram(_) => {
                    std::cmp::min(buf_len, 1 + c::CONFIG_DATAGRAM_MAX_SIZE as usize)
                }
                _ => std::cmp::min(buf_len, c::SYSCALL_IO_BUFSIZE as usize),
            };

            let buf_ptr = unsafe {
                c::process_getWriteablePtr(sys.process, sys.thread, buf_ptr, size_needed as u64)
            };
            Some(unsafe { std::slice::from_raw_parts_mut(buf_ptr as *mut u8, size_needed) })
        } else {
            Some(&mut [][..])
        }
    } else {
        None
    };

    /*
    let mut buf = {
        // TODO: dynamically compute size based on how much data is actually available in the descriptor
        let size_needed = match socket {
            // we should not truncate datagram messages
            socket::SocketFile::InetDgram(_) => {
                std::cmp::min(buf_len, 1 + c::CONFIG_DATAGRAM_MAX_SIZE as usize)
            }
            _ => std::cmp::min(buf_len, c::SYSCALL_IO_BUFSIZE as usize),
        };

        let buf_ptr = unsafe {
            c::process_getWriteablePtr(sys.process, sys.thread, buf_ptr, size_needed as u64)
        };
        unsafe { std::slice::from_raw_parts_mut(buf_ptr as *mut u8, size_needed) }
    };
    */

    if let Some(ref buf) = buf {
        debug!("Attempting to recv {} bytes", buf.len());
    }

    // call the socket's recvfrom(), and run any resulting events
    let (from_addr, result) =
        EventQueue::queue_and_run(|event_queue| socket.borrow_mut().recvfrom(buf, event_queue));

    // TODO: we probably want Rust to store nix addresses instead
    /*
    if addr_ptr.val != 0 && addr_len_ptr.val != 0 {
        let addr_len_ptr =
            unsafe { c::process_getMutablePtr(sys.process, sys.thread, addr_len_ptr, std::mem::size_of<libc::socklen_t>() as u64) };
        let mut addr_len = unsafe { &mut *(addr_len_ptr as *mut libc::socklen_t) };

        let addr_size_needed = std::cmp::min(addr_len, c::SYSCALL_IO_BUFSIZE as usize);
        let addr_ptr =
            unsafe { c::process_getWriteablePtr(sys.process, sys.thread, addr_ptr, addr_size_needed as u64) };
        let mut addr = unsafe { std::slice::from_raw_parts_mut(addr_ptr as *mut u8, addr_size_needed) };


    }
    */

    // if the syscall would block, it's a blocking descriptor, and the `MSG_DONTWAIT` flag is set
    if result == SyscallReturn::Error(nix::errno::EWOULDBLOCK)
        && !file_flags.contains(FileFlags::NONBLOCK)
        && flags & libc::MSG_DONTWAIT == 0
    {
        let trigger = Trigger::from_posix_file(posix_file, FileStatus::READABLE);

        return c::SysCallReturn {
            state: c::SysCallReturnState_SYSCALL_BLOCK,
            retval: c::SysCallReg { as_i64: 0i64 },
            cond: unsafe { c::syscallcondition_new(trigger.into(), std::ptr::null_mut()) },
        };
    }

    // if the addr is non-null and the addr len is non-null
    if addr_ptr.val != 0 && addr_len_ptr.val != 0 {
        if let Some(from_addr) = from_addr {
            let addr_len_ptr = unsafe {
                c::process_getMutablePtr(
                    sys.process,
                    sys.thread,
                    addr_len_ptr,
                    std::mem::size_of::<libc::socklen_t>() as u64,
                )
            };
            let mut addr_len = unsafe { &mut *(addr_len_ptr as *mut libc::socklen_t) };

            let mut addr_ptr = if *addr_len > 0 {
                let addr_size_needed = std::cmp::min(*addr_len, c::SYSCALL_IO_BUFSIZE) as usize;
                let addr_ptr = unsafe {
                    c::process_getWriteablePtr(
                        sys.process,
                        sys.thread,
                        addr_ptr,
                        addr_size_needed as u64,
                    )
                };
                //Some(unsafe { std::slice::from_raw_parts_mut(addr_ptr as *mut u8, addr_size_needed) })
                Some(addr_ptr as *mut u8)
            } else {
                None
            };

            if let Some(mut addr_ptr) = addr_ptr {
                let (from_addr, from_len) = from_addr.as_ffi_pair();
                let len_to_copy = std::cmp::min(*addr_len, from_len);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        from_addr as *const _ as *const u8,
                        addr_ptr,
                        len_to_copy as usize,
                    )
                };

                *addr_len = len_to_copy;
            }
        }
    }

    result.into()
}

fn implicit_bind(
    socket: &socket::SocketFile,
    peer_addr: &Option<nix::sys::socket::SockAddr>,
    sys: &mut c::SysCallHandler,
) -> Option<c::SysCallReturn> {
    let addr = peer_addr;

    // if the socket is not bound
    if socket.borrow().get_bound_address().is_none() {
        let temp_addr = addr.or(socket.borrow().get_peer_address());

        // if the socket is an inet dgram socket and the address is an inet address
        if let (
            socket::SocketFile::InetDgram(inet_socket),
            Some(nix::sys::socket::SockAddr::Inet(inet_addr)),
        ) = (socket, temp_addr)
        {
            // automatically bind the socket
            let bind_ip = if inet_addr.ip().to_std().is_loopback() {
                inet_addr.ip()
            } else {
                // TODO: is this right? what if the default address is on a different interface from the default?
                // should we bind to INADDR_ANY?
                let ip_be = unsafe { c::address_toNetworkIP(c::host_getDefaultAddress(sys.host)) };
                let ip = u32::from_be(ip_be).to_be_bytes();
                nix::sys::socket::IpAddr::new_v4(ip[0], ip[1], ip[2], ip[3])
            };

            let bind_ip = match bind_ip {
                nix::sys::socket::IpAddr::V4(x) => x,
                _ => {
                    warn!("Cannot bind to an IPv6 address");
                    return Some(SyscallReturn::Error(nix::errno::Errno::EINVAL).into());
                }
            };

            let protocol_type = inet_socket.borrow().get_protocol_version();

            let bind_ip_be = u32::from_be_bytes(bind_ip.octets()).to_be();
            let bind_port_be =
                unsafe { c::host_getRandomFreePort(sys.host, protocol_type, bind_ip_be, 0, 0) };

            // ephemeral port unavailable
            if (bind_port_be == 0) {
                info!("binding required an ephemeral port and none are available");
                return Some(SyscallReturn::Error(nix::errno::Errno::EADDRNOTAVAIL).into());
            }

            let bind_port = u16::from_be(bind_port_be);

            // TODO: why do we remove the peer address here?
            //socket.borrow_mut().set_peer_address(None).unwrap();
            socket
                .borrow_mut()
                .set_bound_address(nix::sys::socket::SockAddr::Inet(
                    nix::sys::socket::InetAddr::new(
                        nix::sys::socket::IpAddr::V4(bind_ip),
                        bind_port,
                    ),
                ))
                .unwrap();

            // set associations
            unsafe {
                c::host_associateInterfaceSocketFile(sys.host, socket as *const _, bind_ip_be)
            };
            debug!("Bound socket to {}:{}", bind_ip, bind_port);
        }
    }

    None
}

pub fn sendto(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let buf_ptr = unsafe { args.args[1].as_ptr };
    let buf_len = unsafe { args.args[2].as_u64 } as libc::size_t;
    let flags = unsafe { args.args[3].as_u64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[4].as_ptr };
    let addr_len = unsafe { args.args[5].as_u64 } as libc::socklen_t;

    sendto_helper(sys, args, fd, buf_ptr, buf_len, flags, addr_ptr, addr_len)
}

pub fn sendto_helper(
    sys: &mut c::SysCallHandler,
    args: &c::SysCallArgs,
    fd: libc::c_int,
    buf_ptr: c::PluginPtr,
    buf_len: libc::size_t,
    flags: libc::c_int,
    addr_ptr: c::PluginPtr,
    addr_len: libc::socklen_t,
) -> c::SysCallReturn {
    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_sendto(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let posix_file = desc.get_file();
    let file_flags = posix_file.borrow().get_flags();

    let socket = match posix_file {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // TODO: we handle this in the socket's sendto(), so should we check it here?
    // need a non-null buffer
    if buf_ptr.val == 0 {
        return SyscallReturn::Error(nix::errno::Errno::EFAULT).into();
    }

    // need a non-negative size
    if buf_len < 0 {
        info!("Invalid length {} provided on descriptor {}", buf_len, fd);
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // TODO: dynamically compute size based on how much data is actually available in the descriptor
    let size_needed = match socket {
        // we should not truncate datagram messages
        socket::SocketFile::InetDgram(_) => {
            std::cmp::min(buf_len, 1 + c::CONFIG_DATAGRAM_MAX_SIZE as usize)
        }
        _ => std::cmp::min(buf_len, c::SYSCALL_IO_BUFSIZE as usize),
    };

    let buf = if buf_len > 0 {
        let buf_ptr = unsafe {
            c::process_getReadablePtr(sys.process, sys.thread, buf_ptr, size_needed as u64)
        };
        Some(unsafe { std::slice::from_raw_parts(buf_ptr as *mut u8, size_needed) })
    } else {
        Some(&[][..])
    };

    let addr = if addr_ptr.val != 0 {
        let addr_ptr = unsafe {
            c::process_getReadablePtr(sys.process, sys.thread, addr_ptr, addr_len as u64)
        };
        let addr_ptr = addr_ptr as *const libc::sockaddr;

        match sockaddr_to_nix(addr_ptr, addr_len as usize) {
            Ok(x) => Some(x),
            Err(x) => {
                warn!("Unable to convert the sockaddr: {}", x);
                return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
            }
        }
    } else {
        None
    };

    if let Some(rv) = implicit_bind(socket, &addr, sys) {
        return rv;
    }

    /*
    // if the socket is not bound
    if socket.borrow().get_bound_address().is_none() {
        let temp_addr = addr.or(socket.borrow().get_peer_address());

        // if the socket is an inet dgram socket and the address is an inet address
        if let (
            socket::SocketFile::InetDgram(inet_socket),
            Some(nix::sys::socket::SockAddr::Inet(inet_addr)),
        ) = (socket, temp_addr)
        {
            // automatically bind the socket
            let bind_ip = if inet_addr.ip().to_std().is_loopback() {
                inet_addr.ip()
            } else {
                // TODO: is this right? what if the default address is on a different interface from the default?
                // should we bind to INADDR_ANY?
                let ip_be = unsafe { c::address_toNetworkIP(c::host_getDefaultAddress(sys.host)) };
                let ip = u32::from_be(ip_be).to_be_bytes();
                nix::sys::socket::IpAddr::new_v4(ip[0], ip[1], ip[2], ip[3])
            };

            let bind_ip = match bind_ip {
                nix::sys::socket::IpAddr::V4(x) => x,
                _ => {
                    warn!("Cannot bind to an IPv6 address");
                    return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
                }
            };

            let protocol_type = inet_socket.borrow().get_protocol_version();

            let bind_ip_be = u32::from_be_bytes(bind_ip.octets()).to_be();
            let bind_port_be =
                unsafe { c::host_getRandomFreePort(sys.host, protocol_type, bind_ip_be, 0, 0) };

            // ephemeral port unavailable
            if (bind_port_be == 0) {
                info!("binding required an ephemeral port and none are available");
                return SyscallReturn::Error(nix::errno::Errno::EADDRNOTAVAIL).into();
            }

            let bind_port = u16::from_be(bind_port_be);

            // TODO: why do we remove the peer address here?
            //socket.borrow_mut().set_peer_address(None).unwrap();
            socket
                .borrow_mut()
                .set_bound_address(nix::sys::socket::SockAddr::Inet(
                    nix::sys::socket::InetAddr::new(
                        nix::sys::socket::IpAddr::V4(bind_ip),
                        bind_port,
                    ),
                ))
                .unwrap();

            // set associations
            unsafe {
                c::host_associateInterfaceSocketFile(sys.host, socket as *const _, bind_ip_be)
            };
            debug!("Bound socket to {}:{}", bind_ip, bind_port);
        }
    }
    */

    if let Some(ref buf) = buf {
        debug!("Attempting to send {} bytes to {:?}", buf.len(), addr);
    }

    // call the socket's sendto(), and run any resulting events
    let result =
        EventQueue::queue_and_run(|event_queue| socket.borrow_mut().sendto(buf, addr, event_queue));

    let bound_addr = socket.borrow().get_bound_address();

    if let Some(nix::sys::socket::SockAddr::Inet(bound_addr)) = bound_addr {
        match bound_addr.ip() {
            nix::sys::socket::IpAddr::V4(bound_addr) => {
                let bound_addr = u32::from_be_bytes(bound_addr.octets()).to_be();
                let interface = unsafe { c::host_lookupInterface(sys.host, bound_addr) };
                unsafe { c::networkinterface_socketFileWantsSend(interface, socket as *const _) };
            }
            _ => unimplemented!(),
        }
    }

    // if the syscall would block, it's a blocking descriptor, and the `MSG_DONTWAIT` flag is set
    if result == SyscallReturn::Error(nix::errno::EWOULDBLOCK)
        && !file_flags.contains(FileFlags::NONBLOCK)
        && flags & libc::MSG_DONTWAIT == 0
    {
        let trigger = Trigger::from_posix_file(posix_file, FileStatus::WRITABLE);

        return c::SysCallReturn {
            state: c::SysCallReturnState_SYSCALL_BLOCK,
            retval: c::SysCallReg { as_i64: 0i64 },
            cond: unsafe { c::syscallcondition_new(trigger.into(), std::ptr::null_mut()) },
        };
    }

    result.into()
}

pub fn connect(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[1].as_ptr };
    let addr_len = unsafe { args.args[2].as_u64 } as libc::socklen_t;

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_connect(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let posix_file = desc.get_file();

    let socket = match posix_file {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // make sure the addr PluginPtr is not NULL
    if addr_ptr.val == 0 {
        info!("binding to a NULL address is invalid");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    let addr_ptr =
        unsafe { c::process_getReadablePtr(sys.process, sys.thread, addr_ptr, addr_len as u64) };
    let addr_ptr = addr_ptr as *const libc::sockaddr;

    let family = match get_addr_family(addr_ptr, addr_len as usize) {
        Ok(x) => x as libc::c_int,
        Err(x) => {
            warn!("Unable to get address family: {}", x);
            return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
        }
    };

    let addr = if family == libc::AF_UNSPEC {
        None
    } else {
        match sockaddr_to_nix(addr_ptr, addr_len as usize) {
            Ok(x) => Some(x),
            Err(x) => {
                warn!("Unable to convert the sockaddr: {}", x);
                return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
            }
        }
    };

    // call the socket's connect(), and run any resulting events
    let result =
        EventQueue::queue_and_run(|event_queue| socket.borrow_mut().connect(addr, event_queue));

    if let Some(rv) = implicit_bind(socket, &addr, sys) {
        return rv;
    }

    result.into()
}

pub fn getsockname(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[1].as_ptr };
    let addr_len_ptr = unsafe { args.args[2].as_ptr };

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_getsockname(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let posix_file = desc.get_file();

    let socket = match posix_file {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // make sure the addr and addr_len is not NULL
    if addr_ptr.val == 0 || addr_len_ptr.val == 0 {
        info!("Address info is null");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    let addr_len_ptr = unsafe {
        c::process_getMutablePtr(
            sys.process,
            sys.thread,
            addr_len_ptr,
            std::mem::size_of::<libc::socklen_t>() as u64,
        )
    };
    let addr_len = unsafe { &mut *(addr_len_ptr as *mut libc::socklen_t) };

    let addr_ptr =
        unsafe { c::process_getWriteablePtr(sys.process, sys.thread, addr_ptr, *addr_len as u64) };
    let addr_ptr = addr_ptr as *const libc::sockaddr;

    let bound_addr = socket.borrow().get_bound_address();

    // if the socket is not bound, use an empty sockaddr instead
    let addr_to_write = match bound_addr {
        Some(x) => x,
        None => empty_sockaddr(socket.borrow().address_family() as libc::sa_family_t).unwrap(),
    };

    debug!("Returning socket address of {}", addr_to_write);

    let (sock_addr, sock_len) = addr_to_write.as_ffi_pair();
    let sock_addr = sock_addr as *const libc::sockaddr;

    let len_to_copy = std::cmp::min(*addr_len, sock_len) as usize;

    unsafe { std::ptr::copy::<u8>(sock_addr as *const u8, addr_ptr as *mut u8, len_to_copy) };

    *addr_len = sock_len;

    SyscallReturn::Success(0).into()
}

pub fn getpeername(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[1].as_ptr };
    let addr_len_ptr = unsafe { args.args[2].as_ptr };

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_getpeername(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let posix_file = desc.get_file();

    let socket = match posix_file {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // make sure the addr and addr_len is not NULL
    if addr_ptr.val == 0 || addr_len_ptr.val == 0 {
        info!("Address info is null");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    let addr_len_ptr = unsafe {
        c::process_getMutablePtr(
            sys.process,
            sys.thread,
            addr_len_ptr,
            std::mem::size_of::<libc::socklen_t>() as u64,
        )
    };
    let addr_len = unsafe { &mut *(addr_len_ptr as *mut libc::socklen_t) };

    let addr_ptr =
        unsafe { c::process_getWriteablePtr(sys.process, sys.thread, addr_ptr, *addr_len as u64) };
    let addr_ptr = addr_ptr as *const libc::sockaddr;

    if let Some(addr_to_write) = socket.borrow().get_peer_address() {
        let (sock_addr, sock_len) = addr_to_write.as_ffi_pair();
        let sock_addr = sock_addr as *const libc::sockaddr;

        let len_to_copy = std::cmp::min(*addr_len, sock_len) as usize;

        unsafe { std::ptr::copy::<u8>(sock_addr as *const u8, addr_ptr as *mut u8, len_to_copy) };

        *addr_len = sock_len;

        SyscallReturn::Success(0).into()
    } else {
        SyscallReturn::Error(nix::errno::Errno::ENOTCONN).into()
    }
}

pub fn listen(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let backlog = unsafe { args.args[1].as_i64 } as libc::c_int;

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_listen(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    return SyscallReturn::Error(nix::errno::Errno::EOPNOTSUPP).into();
}

pub fn accept(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[1].as_ptr };
    let addr_len_ptr = unsafe { args.args[2].as_ptr };

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_accept(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    return SyscallReturn::Error(nix::errno::Errno::EOPNOTSUPP).into();
}

pub fn accept4(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let addr_ptr = unsafe { args.args[1].as_ptr };
    let addr_len_ptr = unsafe { args.args[2].as_ptr };
    let flags = unsafe { args.args[3].as_i64 } as libc::c_int;

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_accept4(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    return SyscallReturn::Error(nix::errno::Errno::EOPNOTSUPP).into();
}

pub fn shutdown(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let how = unsafe { args.args[1].as_i64 } as libc::c_int;

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_shutdown(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    debug!("Trying to shutdown on socket {} with how {}", fd, how);

    let how = match how {
        libc::SHUT_RD => nix::sys::socket::Shutdown::Read,
        libc::SHUT_WR => nix::sys::socket::Shutdown::Write,
        libc::SHUT_RDWR => nix::sys::socket::Shutdown::Both,
        _ => {
            info!("Invalid how: {}", how);
            return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
        }
    };

    // call the socket's shutdown(), and run any resulting events
    EventQueue::queue_and_run(|event_queue| socket.borrow_mut().shutdown(how)).into()
}

pub fn getsockopt(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let level = unsafe { args.args[1].as_i64 } as libc::c_int;
    let optname = unsafe { args.args[2].as_i64 } as libc::c_int;
    let optval_ptr = unsafe { args.args[3].as_ptr };
    let optval_len_ptr = unsafe { args.args[4].as_ptr };

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_getsockopt(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    debug!(
        "Trying to getsockopt on socket {} at level {} for opt {}",
        fd, level, optname
    );

    // make sure the optval_len is not NULL
    if optval_len_ptr.val == 0 {
        info!("optlen is null");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    let optval_len_ptr = unsafe {
        c::process_getMutablePtr(
            sys.process,
            sys.thread,
            optval_len_ptr,
            std::mem::size_of::<libc::socklen_t>() as u64,
        )
    };
    let optval_len = unsafe { &mut *(optval_len_ptr as *mut libc::socklen_t) };

    // return early if there is no data
    if *optval_len == 0 {
        return SyscallReturn::Success(0).into();
    }

    // the pointer must be non-null
    if optval_ptr.val == 0 {
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // call the socket's getsockopt(), and run any resulting events
    EventQueue::queue_and_run(|event_queue| {
        socket
            .borrow()
            .getsockopt(sys, level, optname, optval_ptr, optval_len)
    })
    .into()
}

pub fn setsockopt(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
    let fd = unsafe { args.args[0].as_i64 } as libc::c_int;
    let level = unsafe { args.args[1].as_i64 } as libc::c_int;
    let optname = unsafe { args.args[2].as_i64 } as libc::c_int;
    let optval_ptr = unsafe { args.args[3].as_ptr };
    let optval_len = unsafe { args.args[4].as_u64 } as libc::socklen_t;

    // get the descriptor, or return early if it doesn't exist
    let desc = match syscall::get_descriptor(fd, sys.process) {
        Ok(d) => unsafe { &mut *d },
        Err(errno) => return SyscallReturn::Error(errno).into(),
    };

    // if it's a legacy descriptor, use the C syscall handler instead
    let desc = match desc {
        CompatDescriptor::New(d) => d,
        CompatDescriptor::Legacy(_) => unsafe {
            return c::syscallhandler_setsockopt(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    debug!(
        "Trying to setsockopt on socket {} at level {} for opt {}",
        fd, level, optname
    );

    // return early if there is no data
    if optval_len == 0 {
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // the pointer must be non-null
    if optval_ptr.val == 0 {
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // call the socket's setsockopt(), and run any resulting events
    EventQueue::queue_and_run(|event_queue| {
        socket
            .borrow_mut()
            .setsockopt(sys, level, optname, optval_ptr, optval_len)
    })
    .into()
}

mod export {
    use super::*;

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_socket(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        socket(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_bind(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        bind(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_recvfrom(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        recvfrom(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_sendto(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        sendto(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_connect(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        connect(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_getsockname(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        getsockname(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_getpeername(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        getpeername(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_listen(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        listen(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_accept(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        accept(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_accept4(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        accept4(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_shutdown(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        shutdown(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_getsockopt(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        getsockopt(unsafe { &mut *sys }, unsafe { &*args })
    }

    #[no_mangle]
    pub extern "C" fn rustsyscallhandler_setsockopt(
        sys: *mut c::SysCallHandler,
        args: *const c::SysCallArgs,
    ) -> c::SysCallReturn {
        assert!(!sys.is_null() && !args.is_null());
        setsockopt(unsafe { &mut *sys }, unsafe { &*args })
    }
}
