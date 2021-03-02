use crate::cshadow as c;
use crate::host::descriptor::socket;
use crate::host::descriptor::{
    CompatDescriptor, Descriptor, DescriptorFlags, FileFlags, FileMode, FileStatus, PosixFile,
    SyscallReturn,
};
use crate::host::syscall;
use crate::host::syscall::Trigger;
use crate::utility::event_queue::EventQueue;

use std::convert::TryInto;
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

pub fn bind(sys: &mut c::SysCallHandler, args: &c::SysCallArgs) -> c::SysCallReturn {
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
            return c::syscallhandler_bind(
                sys as *mut c::SysCallHandler,
                args as *const c::SysCallArgs,
            );
        },
    };

    debug!("Trying to bind socket fd {}", fd);

    // get the socket for the descriptor
    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => {
            return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into();
        }
    };

    // it's an error if the socket is already bound
    if let Some(bound_addr) = socket.borrow().get_bound_address() {
        debug!("Socket fd {} is already bound to {}", fd, bound_addr);
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // get the bind address
    let addr = match syscall::get_readable_ptr::<libc::sockaddr>(
        sys.process,
        sys.thread,
        addr_ptr,
        addr_len.try_into().unwrap(),
    ) {
        syscall::ResolvedPluginPtr::Address(ptr) => {
            match unsafe { sockaddr_to_nix(ptr, addr_len.try_into().unwrap()) } {
                Ok(x) => x,
                Err(x) => {
                    warn!("Unable to convert the sockaddr to a nix object: {}", x);
                    return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
                }
            }
        }
        syscall::ResolvedPluginPtr::Null => {
            debug!("Cannot bind fd {} to a NULL address", fd);
            return SyscallReturn::Error(nix::errno::Errno::EFAULT).into();
        }
        syscall::ResolvedPluginPtr::ZeroLen | syscall::ResolvedPluginPtr::LenTooSmall => {
            return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
        }
    };

    // bind the address to the socket
    if let nix::sys::socket::SockAddr::Inet(addr) = addr {
        if let Some(x) = bind_to_interface(socket, addr, sys) {
            return x;
        }
    } else {
        warn!("Binding only supports AF_INET sockets");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

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

    // get the socket for the descriptor
    let socket = match posix_file {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // address length pointer cannot be null if the address buffer is non-null
    if addr_ptr.val != 0 && addr_len_ptr.val == 0 {
        debug!("When receiving with a null addr, the addr len must also be null");
        return SyscallReturn::Error(nix::errno::Errno::EFAULT).into();
    }

    // TODO: dynamically compute size based on how much data is actually available in the descriptor
    let size_needed = std::cmp::min(
        buf_len,
        match socket {
            // we should not truncate datagram messages
            socket::SocketFile::InetDgram(_) => 1 + c::CONFIG_DATAGRAM_MAX_SIZE as usize,
            _ => c::SYSCALL_IO_BUFSIZE as usize,
        },
    );

    let mut buf =
        match syscall::get_writable_ptr::<u8>(sys.process, sys.thread, buf_ptr, size_needed) {
            syscall::MutResolvedPluginPtr::Address(ptr) => {
                Some(unsafe { std::slice::from_raw_parts_mut(ptr, size_needed) })
            }
            syscall::MutResolvedPluginPtr::ZeroLen => Some(&mut [][..]),
            syscall::MutResolvedPluginPtr::Null => None,
            syscall::MutResolvedPluginPtr::LenTooSmall => unreachable!(),
        };

    if let Some(ref buf) = buf {
        debug!("Attempting to recv {} bytes", buf.len());
    }

    // call the socket's recvfrom(), and run any resulting events
    let (from_addr, result) =
        EventQueue::queue_and_run(|event_queue| socket.borrow_mut().recvfrom(buf, event_queue));

    // if the syscall would block, it's a blocking descriptor, and the `MSG_DONTWAIT` flag is not set
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

    if let Some(from_addr) = from_addr {
        if addr_ptr.val != 0 && addr_len_ptr.val != 0 {
            copy_sockaddr_to_plugin(sys.process, sys.thread, from_addr, addr_ptr, addr_len_ptr);
        }
    }

    result.into()
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

    // get the socket for the descriptor
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
        debug!("Invalid length {} provided on descriptor {}", buf_len, fd);
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
                warn!("Unable to convert the sockaddr to a nix object: {}", x);
                return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
            }
        }
    } else {
        None
    };

    // if an unbound inet socket, bind the socket
    if let Some(nix::sys::socket::SockAddr::Inet(addr)) = addr {
        if socket.borrow().get_bound_address().is_none() {
            if let Some(rv) = implicit_bind(socket, &Some(addr.ip()), sys) {
                return rv;
            }
        }
    }

    if let Some(ref buf) = buf {
        debug!("Attempting to send {} bytes to {:?}", buf.len(), addr);
    }

    // call the socket's sendto(), and run any resulting events
    let result =
        EventQueue::queue_and_run(|event_queue| socket.borrow_mut().sendto(buf, addr, event_queue));

    let bound_addr = socket.borrow().get_bound_address();

    // if an inet socket, inform the network interface
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

    // if the syscall would block, it's a blocking descriptor, and the `MSG_DONTWAIT` flag is not set
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

    // get the socket for the descriptor
    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // make sure the addr PluginPtr is not NULL
    if addr_ptr.val == 0 {
        debug!("binding to a NULL address is invalid");
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
                warn!("Unable to convert the sockaddr to a nix object: {}", x);
                return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
            }
        }
    };

    // call the socket's connect(), and run any resulting events
    let result =
        EventQueue::queue_and_run(|event_queue| socket.borrow_mut().connect(addr, event_queue));

    // if an unbound inet socket, bind the socket
    if socket.borrow().get_bound_address().is_none() {
        if let Some(nix::sys::socket::SockAddr::Inet(addr)) = addr {
            if let Some(rv) = implicit_bind(socket, &Some(addr.ip()), sys) {
                return rv;
            }
        }
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

    // get the socket for the descriptor
    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // make sure the addr and addr_len is not NULL
    if addr_ptr.val == 0 || addr_len_ptr.val == 0 {
        debug!("Address info is null");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    // if the socket is not bound, use an empty sockaddr instead
    let addr_to_write = match socket.borrow().get_bound_address() {
        Some(x) => x,
        None => empty_sockaddr(socket.borrow().address_family() as libc::sa_family_t).unwrap(),
    };

    debug!("Returning socket address of {}", addr_to_write);

    copy_sockaddr_to_plugin(
        sys.process,
        sys.thread,
        addr_to_write,
        addr_ptr,
        addr_len_ptr,
    );

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

    // get the socket for the descriptor
    let socket = match desc.get_file() {
        PosixFile::Socket(x) => x,
        _ => return SyscallReturn::Error(nix::errno::Errno::ENOTSOCK).into(),
    };

    // make sure the addr and addr_len is not NULL
    if addr_ptr.val == 0 || addr_len_ptr.val == 0 {
        debug!("Address info is null");
        return SyscallReturn::Error(nix::errno::Errno::EINVAL).into();
    }

    if let Some(addr_to_write) = socket.borrow().get_peer_address() {
        debug!("Returning socket address of {}", addr_to_write);
        copy_sockaddr_to_plugin(
            sys.process,
            sys.thread,
            addr_to_write,
            addr_ptr,
            addr_len_ptr,
        );
    } else {
        return SyscallReturn::Error(nix::errno::Errno::ENOTCONN).into();
    }

    SyscallReturn::Success(0).into()
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

    // get the socket for the descriptor
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
            debug!("Invalid how: {}", how);
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

    // get the socket for the descriptor
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
        debug!("optlen is null");
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

    // get the socket for the descriptor
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

/// Returns a nix socket address object where only the family is set.
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

/// Copy the socket address to the plugin. Assumes that both plugin pointers are non-NULL. The
/// plugin's address length will be updated to store the size of the socket address, even if
/// greater than the provided buffer size.
fn copy_sockaddr_to_plugin(
    process: *mut c::Process,
    thread: *mut c::Thread,
    addr: nix::sys::socket::SockAddr,
    addr_ptr: c::PluginPtr,
    addr_len_ptr: c::PluginPtr,
) {
    // check that neither address is NULL
    assert!(addr_ptr.val != 0 && addr_len_ptr.val != 0);

    let (from_addr, from_len) = addr.as_ffi_pair();

    let mut addr_len = match syscall::get_mutable_ptr::<libc::socklen_t>(
        process,
        thread,
        addr_len_ptr,
        std::mem::size_of::<libc::socklen_t>(),
    ) {
        syscall::MutResolvedPluginPtr::Address(ptr) => unsafe { &mut *ptr },
        // the address can't be NULL, and we set the length ourselves
        _ => unreachable!(),
    };

    // return early if the address length is 0
    if *addr_len <= 0 {
        *addr_len = from_len;
        return;
    }

    let mut addr_ptr =
        match syscall::get_writable_ptr::<u8>(process, thread, addr_ptr, *addr_len as usize) {
            syscall::MutResolvedPluginPtr::Address(ptr) => unsafe { &mut *ptr },
            // the address can't be NULL, and we know the length is not 0
            _ => unreachable!(),
        };

    let len_to_copy = std::cmp::min(*addr_len, from_len) as usize;
    unsafe {
        std::ptr::copy_nonoverlapping(from_addr as *const _ as *const u8, addr_ptr, len_to_copy)
    };

    *addr_len = from_len;
}

fn addr_to_network_byte_order(
    addr: nix::sys::socket::InetAddr,
) -> Result<(libc::in_addr_t, libc::in_port_t), String> {
    match addr.ip() {
        nix::sys::socket::IpAddr::V4(x) => {
            Ok((u32::from_be_bytes(x.octets()).to_be(), addr.port().to_be()))
        }
        //_ => unimplemented!("Cannot bind on an IPv6 address"),
        _ => Err("Cannot convert an IPv6 address to network byte order".into()),
    }
}

fn bind_to_interface(
    socket: &socket::SocketFile,
    addr: nix::sys::socket::InetAddr,
    sys: &mut c::SysCallHandler,
) -> Option<c::SysCallReturn> {
    let (addr_ip_be, addr_port_be) = addr_to_network_byte_order(addr).unwrap();

    // make sure this is an inet socket
    if socket.borrow().address_family() != nix::sys::socket::AddressFamily::Inet {
        debug!(
            "Only inet sockets can be bound to the network interface, not {:?}",
            socket.borrow().address_family()
        );
        return Some(SyscallReturn::Error(nix::errno::Errno::EINVAL).into());
    }

    // make sure we have an interface at that address
    if unsafe { c::host_doesInterfaceExist(sys.host, addr_ip_be) } == 0 {
        debug!("No network interface exists for the bind address {}", addr);
        return Some(SyscallReturn::Error(nix::errno::Errno::EINVAL).into());
    }

    // each protocol type gets its own ephemeral port mapping
    let protocol_type = socket.borrow().get_protocol_version();

    // get a free ephemeral port if they didn't specify one
    let (addr, addr_ip_be, addr_port_be) = {
        if addr_port_be == 0 {
            let new_addr_port_be =
                unsafe { c::host_getRandomFreePort(sys.host, protocol_type, addr_ip_be, 0, 0) };

            // update the address with the same ip, but new port
            let new_addr =
                nix::sys::socket::InetAddr::new(addr.ip(), u16::from_be(new_addr_port_be));

            debug!("Binding to generated ephemeral port {}", new_addr);

            (new_addr, addr_ip_be, new_addr_port_be)
        } else {
            (addr, addr_ip_be, addr_port_be)
        }
    };

    // ephemeral port unavailable
    if (addr.port() == 0) {
        debug!("Binding required an ephemeral port and none are available");
        return Some(SyscallReturn::Error(nix::errno::Errno::EADDRINUSE).into());
    }

    // make sure the port is available at this address for this protocol
    if unsafe {
        c::host_isInterfaceAvailable(sys.host, protocol_type, addr_ip_be, addr_port_be, 0, 0)
    } == 0
    {
        debug!("The provided address {} is not available", addr);
        return Some(SyscallReturn::Error(nix::errno::Errno::EADDRINUSE).into());
    }

    socket
        .borrow_mut()
        .set_bound_address(nix::sys::socket::SockAddr::Inet(addr))
        .unwrap();

    // set associations
    // TODO: should we box the socket pointer?
    unsafe { c::host_associateInterfaceSocketFile(sys.host, socket as *const _, addr_ip_be) };

    None
}

fn implicit_bind(
    socket: &socket::SocketFile,
    remote_ip: &Option<nix::sys::socket::IpAddr>,
    sys: &mut c::SysCallHandler,
) -> Option<c::SysCallReturn> {
    assert!(socket.borrow().get_bound_address().is_none());

    let bind_ip = match remote_ip {
        Some(ip) => *ip,
        None => match socket.borrow().get_peer_address() {
            Some(nix::sys::socket::SockAddr::Inet(peer_addr)) => peer_addr.ip(),
            _ => {
                debug!("Socket does not have an inet peer address");
                return Some(SyscallReturn::Error(nix::errno::Errno::EINVAL).into());
            }
        },
    };

    // choose the address to bind to
    let bind_ip = if bind_ip.to_std().is_loopback() {
        bind_ip
    } else {
        // TODO: is this right? what if the default address is on a different interface from the default?
        // should we bind to INADDR_ANY?
        let ip_be = unsafe { c::address_toNetworkIP(c::host_getDefaultAddress(sys.host)) };
        let ip = u32::from_be(ip_be).to_be_bytes();
        nix::sys::socket::IpAddr::new_v4(ip[0], ip[1], ip[2], ip[3])
    };

    bind_to_interface(socket, nix::sys::socket::InetAddr::new(bind_ip, 0), sys)
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
