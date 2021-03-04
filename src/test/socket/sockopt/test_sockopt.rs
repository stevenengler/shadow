/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */

use std::convert::TryInto;

use test_utils::set;
use test_utils::AsMutPtr;
use test_utils::TestEnvironment as TestEnv;

#[derive(Debug, Clone)]
struct GetsockoptArguments {
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    optval: Option<Vec<u8>>,
    optlen: Option<libc::socklen_t>,
}

#[derive(Debug, Clone)]
struct SetsockoptArguments {
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    optval: Option<Vec<u8>>,
    optlen: libc::socklen_t,
}

impl GetsockoptArguments {
    pub fn new(
        fd: libc::c_int,
        level: libc::c_int,
        optname: libc::c_int,
        optval: Option<Vec<u8>>,
    ) -> Self {
        let len = optval.as_ref().map_or(0, |v| v.len());
        Self {
            fd,
            level,
            optname,
            optlen: Some(len as libc::socklen_t),
            optval,
        }
    }
}

impl SetsockoptArguments {
    pub fn new(
        fd: libc::c_int,
        level: libc::c_int,
        optname: libc::c_int,
        optval: Option<Vec<u8>>,
    ) -> Self {
        let len = optval.as_ref().map_or(0, |v| v.len());
        Self {
            fd,
            level,
            optname,
            optlen: len as libc::socklen_t,
            optval,
        }
    }
}

fn main() -> Result<(), String> {
    // should we restrict the tests we run?
    let filter_shadow_passing = std::env::args().any(|x| x == "--shadow-passing");
    let filter_libc_passing = std::env::args().any(|x| x == "--libc-passing");
    // should we summarize the results rather than exit on a failed test
    let summarize = std::env::args().any(|x| x == "--summarize");

    let mut tests = get_tests();
    if filter_shadow_passing {
        tests = tests
            .into_iter()
            .filter(|x| x.passing(TestEnv::Shadow))
            .collect()
    }
    if filter_libc_passing {
        tests = tests
            .into_iter()
            .filter(|x| x.passing(TestEnv::Libc))
            .collect()
    }

    test_utils::run_tests(&tests, summarize)?;

    println!("Success.");
    Ok(())
}

fn get_tests() -> Vec<test_utils::ShadowTest<(), String>> {
    let mut tests: Vec<test_utils::ShadowTest<_, _>> = vec![
        test_utils::ShadowTest::new(
            "test_invalid_fd",
            test_invalid_fd,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_non_existent_fd",
            test_non_existent_fd,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_non_socket_fd",
            test_non_socket_fd,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_long_len",
            test_long_len,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_short_len",
            test_short_len,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_zero_len",
            test_zero_len,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_null_val",
            test_null_val,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_null_val_zero_len",
            test_null_val_zero_len,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_null_val_nonzero_len",
            test_null_val_nonzero_len,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_null_val_null_len",
            test_null_val_null_len,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
        test_utils::ShadowTest::new(
            "test_invalid_level",
            test_invalid_level,
            set![TestEnv::Libc, TestEnv::Shadow],
        ),
    ];

    let domains = [libc::AF_INET];
    let sock_types = [libc::SOCK_STREAM, libc::SOCK_DGRAM];

    for &domain in domains.iter() {
        for &sock_type in sock_types.iter() {
            // add details to the test names to avoid duplicates
            let append_args = |s| format!("{} <domain={},sock_type={}>", s, domain, sock_type);

            let more_tests: Vec<test_utils::ShadowTest<_, _>> = vec![
                test_utils::ShadowTest::new(
                    &append_args("test_so_sndbuf"),
                    move || test_so_sndbuf(domain, sock_type),
                    set![TestEnv::Libc, TestEnv::Shadow],
                ),
                test_utils::ShadowTest::new(
                    &append_args("test_so_rcvbuf"),
                    move || test_so_rcvbuf(domain, sock_type),
                    set![TestEnv::Libc, TestEnv::Shadow],
                ),
                test_utils::ShadowTest::new(
                    &append_args("test_so_error"),
                    move || test_so_error(domain, sock_type),
                    set![TestEnv::Libc, TestEnv::Shadow],
                ),
                test_utils::ShadowTest::new(
                    &append_args("test_tcp_info"),
                    move || test_tcp_info(domain, sock_type),
                    set![TestEnv::Libc, TestEnv::Shadow],
                ),
                test_utils::ShadowTest::new(
                    &append_args("test_so_sndbuf_with_large_send"),
                    move || test_so_sndbuf_with_large_send(domain, sock_type),
                    set![TestEnv::Libc, TestEnv::Shadow],
                ),
            ];

            tests.extend(more_tests);
        }
    }

    tests
}

/// Test getsockopt() and setsockopt() using an argument that cannot be a fd.
fn test_invalid_fd() -> Result<(), String> {
    let fd = -1;
    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optval = 1024i32.to_ne_bytes();

    let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

    check_getsockopt_call(&mut get_args, &[libc::EBADF])?;
    check_setsockopt_call(&mut set_args, &[libc::EBADF])?;

    Ok(())
}

/// Test getsockopt() and setsockopt() using an argument that could be a fd, but is not.
fn test_non_existent_fd() -> Result<(), String> {
    let fd = 8934;
    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optval = 1024i32.to_ne_bytes();

    let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

    check_getsockopt_call(&mut get_args, &[libc::EBADF])?;
    check_setsockopt_call(&mut set_args, &[libc::EBADF])?;

    Ok(())
}

/// Test getsockopt() and setsockopt() using a valid fd that is not a socket.
fn test_non_socket_fd() -> Result<(), String> {
    let fd = 0;
    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optval = 1024i32.to_ne_bytes();

    let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

    check_getsockopt_call(&mut get_args, &[libc::ENOTSOCK])?;
    check_setsockopt_call(&mut set_args, &[libc::ENOTSOCK])?;

    Ok(())
}

/// Test getsockopt() and setsockopt() using a non-null optval and a long optlen.
fn test_long_len() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optval = 1024u64.to_ne_bytes();

    let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

    test_utils::run_and_close_fds(&[fd], || {
        check_getsockopt_call(&mut get_args, &[])?;
        // the optlen should have changed
        test_utils::result_assert_eq(
            get_args.optlen.as_ref().unwrap(),
            &4,
            "The optlen should have changed",
        )?;
        check_setsockopt_call(&mut set_args, &[])?;
        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using a non-null optval and a short optlen.
fn test_short_len() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optlen = 2usize;

    test_utils::run_and_close_fds(&[fd], || {
        // get the socket's initial sndbuf optval
        let mut args = GetsockoptArguments::new(fd, level, optname, Some(vec![0u8; 4]));
        check_getsockopt_call(&mut args, &[])?;
        let expected_optval = args.optval.unwrap();

        // set the buffer to some dummy values
        let dummy_optval = vec![10u8, 11, 12, 13];

        // get only two bytes of the sndbuf optval
        let mut args = GetsockoptArguments {
            fd,
            level,
            optname,
            optval: Some(dummy_optval.clone()),
            optlen: Some(optlen as u32),
        };

        check_getsockopt_call(&mut args, &[])?;

        // check that only the first two bytes changed
        test_utils::result_assert_eq(
            &args.optval.as_ref().unwrap()[..optlen],
            &expected_optval[..optlen],
            "First bytes should be the expected bytes",
        )?;
        test_utils::result_assert_eq(
            &args.optval.as_ref().unwrap()[optlen..],
            &dummy_optval[optlen..],
            "Remaining bytes should not have changed",
        )?;
        test_utils::result_assert_eq(
            args.optlen.as_ref().unwrap(),
            &(optlen as u32),
            "The optlen should not have changed",
        )?;

        // try setting only two bytes of the sndbuf optval
        let mut args = SetsockoptArguments {
            fd,
            level,
            optname,
            optval: Some(1024i32.to_ne_bytes().into()),
            optlen: optlen as u32,
        };

        check_setsockopt_call(&mut args, &[libc::EINVAL])
    })
}

/// Test getsockopt() and setsockopt() using a non-null optval and a zero optlen.
fn test_zero_len() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optval = 1024i32.to_ne_bytes();
    let optlen = 0;

    let mut get_args = GetsockoptArguments {
        fd,
        level,
        optname,
        optval: Some(optval.into()),
        optlen: Some(optlen),
    };
    let mut set_args = SetsockoptArguments {
        fd,
        level,
        optname,
        optval: Some(optval.into()),
        optlen,
    };

    test_utils::run_and_close_fds(&[fd], || {
        check_getsockopt_call(&mut get_args, &[])?;
        // the optval and optlen should not have changed
        test_utils::result_assert_eq(
            &get_args.optval.as_ref().unwrap()[..],
            &optval,
            "The optval should not have changed",
        )?;
        test_utils::result_assert_eq(
            get_args.optlen.as_ref().unwrap(),
            &optlen,
            "The optlen should not have changed",
        )?;
        check_setsockopt_call(&mut set_args, &[libc::EINVAL])?;
        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using a null optval and a correct optlen.
fn test_null_val() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optlen = 4;

    let mut get_args = GetsockoptArguments {
        fd,
        level,
        optname,
        optval: None,
        optlen: Some(optlen),
    };
    let mut set_args = SetsockoptArguments {
        fd,
        level,
        optname,
        optval: None,
        optlen,
    };

    test_utils::run_and_close_fds(&[fd], || {
        check_getsockopt_call(&mut get_args, &[libc::EFAULT])?;
        check_setsockopt_call(&mut set_args, &[libc::EFAULT])?;
        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using a null optval and a zero optlen.
fn test_null_val_zero_len() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optlen = 0;

    let mut get_args = GetsockoptArguments {
        fd,
        level,
        optname,
        optval: None,
        optlen: Some(optlen),
    };
    let mut set_args = SetsockoptArguments {
        fd,
        level,
        optname,
        optval: None,
        optlen,
    };

    test_utils::run_and_close_fds(&[fd], || {
        check_getsockopt_call(&mut get_args, &[])?;
        check_setsockopt_call(&mut set_args, &[libc::EINVAL])?;
        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using a null optval and a non-zero optlen.
fn test_null_val_nonzero_len() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optlen = 1;

    let mut get_args = GetsockoptArguments {
        fd,
        level,
        optname,
        optval: None,
        optlen: Some(optlen),
    };
    let mut set_args = SetsockoptArguments {
        fd,
        level,
        optname,
        optval: None,
        optlen,
    };

    test_utils::run_and_close_fds(&[fd], || {
        check_getsockopt_call(&mut get_args, &[libc::EFAULT])?;
        // glibc returns EINVAL but shadow returns EFAULT
        check_setsockopt_call(&mut set_args, &[libc::EINVAL, libc::EFAULT])?;
        Ok(())
    })
}

/// Test getsockopt() using a null optval and a null optlen.
fn test_null_val_null_len() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let mut args = GetsockoptArguments {
        fd,
        level: libc::SOL_SOCKET,
        optname: libc::SO_SNDBUF,
        optval: None,
        optlen: None,
    };

    test_utils::run_and_close_fds(&[fd], || check_getsockopt_call(&mut args, &[libc::EFAULT]))
}

/// Test getsockopt() and setsockopt() using an invalid level.
fn test_invalid_level() -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    // these levels should not be valid for a TCP socket
    let levels = &[-100, -1, libc::SOL_RAW, libc::SOL_UDP, libc::SOL_NETLINK];

    test_utils::run_and_close_fds(&[fd], || {
        for &level in levels {
            let optname = libc::SO_SNDBUF;
            let optval = 1024i32.to_ne_bytes();

            let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
            let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

            // glibc returns EOPNOTSUPP but Shadow returns ENOPROTOOPT
            check_getsockopt_call(&mut get_args, &[libc::EOPNOTSUPP, libc::ENOPROTOOPT])?;
            check_setsockopt_call(&mut set_args, &[libc::ENOPROTOOPT])?;
        }

        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using the SO_SNDBUF option.
fn test_so_sndbuf(domain: libc::c_int, sock_type: libc::c_int) -> Result<(), String> {
    let fd = unsafe { libc::socket(domain, sock_type, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;
    let optvals = [0i32, 512, 1000, 2000, 8192, 16_384];

    test_utils::run_and_close_fds(&[fd], || {
        for &optval in &optvals {
            // The man page (man 7 socket) is incorrect, and the actual minimum doubled value is
            // 2*2048 + some offset. See the definition of SOCK_MIN_SNDBUF in the kernel. We just
            // use 4096 and ignore the offset in these tests.
            let min_sndbuf = 4096;

            bufsize_test_helper(fd, level, optname, optval, min_sndbuf)?;
        }

        Ok(())
    })
}

/// A helper function for TCP sockets to start a server on one fd and connect another fd
/// to it. Returns the accepted fd.
fn tcp_connect_helper(
    fd_client: libc::c_int,
    fd_server: libc::c_int,
    flags: libc::c_int,
) -> libc::c_int {
    // the server address
    let mut server_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK.to_be(),
        },
        sin_zero: [0; 8],
    };

    // bind on the server address
    {
        let rv = unsafe {
            libc::bind(
                fd_server,
                &server_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of_val(&server_addr) as u32,
            )
        };
        assert_eq!(rv, 0);
    }

    // get the assigned port number
    {
        let mut server_addr_size = std::mem::size_of_val(&server_addr) as u32;
        let rv = unsafe {
            libc::getsockname(
                fd_server,
                &mut server_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut server_addr_size as *mut libc::socklen_t,
            )
        };
        assert_eq!(rv, 0);
        assert_eq!(server_addr_size, std::mem::size_of_val(&server_addr) as u32);
    }

    // listen for connections
    {
        let rv = unsafe { libc::listen(fd_server, 10) };
        assert_eq!(rv, 0);
    }

    // connect to the server address
    {
        let rv = unsafe {
            libc::connect(
                fd_client,
                &server_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of_val(&server_addr) as u32,
            )
        };
        assert!(rv == 0 || (rv == -1 && test_utils::get_errno() == libc::EINPROGRESS));
    }

    // shadow needs to run events, otherwise the accept call won't know it
    // has an incoming connection (SYN packet)
    {
        let rv = unsafe { libc::usleep(10000) };
        assert_eq!(rv, 0);
    }

    // accept the connection
    let fd = unsafe { libc::accept4(fd_server, std::ptr::null_mut(), std::ptr::null_mut(), flags) };
    assert!(fd >= 0);

    fd
}

/// A helper function for UDP sockets to bind the server fd and optionally connect
/// the client fd to the server fd. Returns the address that the server is bound to.
fn udp_connect_helper(
    fd_client: libc::c_int,
    fd_server: libc::c_int,
    connect: bool,
) -> libc::sockaddr_in {
    // the server address
    let mut server_addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: libc::INADDR_LOOPBACK.to_be(),
        },
        sin_zero: [0; 8],
    };

    // bind on the server address
    {
        let rv = unsafe {
            libc::bind(
                fd_server,
                &server_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of_val(&server_addr) as u32,
            )
        };
        assert_eq!(rv, 0);
    }

    // get the assigned port number
    {
        let mut server_addr_size = std::mem::size_of_val(&server_addr) as u32;
        let rv = unsafe {
            libc::getsockname(
                fd_server,
                &mut server_addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut server_addr_size as *mut libc::socklen_t,
            )
        };
        assert_eq!(rv, 0);
        assert_eq!(server_addr_size, std::mem::size_of_val(&server_addr) as u32);
    }

    // connect to the server address
    if connect {
        let rv = unsafe {
            libc::connect(
                fd_client,
                &server_addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of_val(&server_addr) as u32,
            )
        };
        assert_eq!(rv, 0);
    }

    server_addr
}

/// Test getsockopt() and setsockopt() using the SO_SNDBUF option while sending more data.
fn test_so_sndbuf_with_large_send(
    domain: libc::c_int,
    sock_type: libc::c_int,
) -> Result<(), String> {
    let fd_server = unsafe { libc::socket(domain, sock_type | libc::SOCK_NONBLOCK, 0) };
    let fd_client = unsafe { libc::socket(domain, sock_type | libc::SOCK_NONBLOCK, 0) };
    assert!(fd_server >= 0);
    assert!(fd_client >= 0);
    
    // connect the client fd to the server
    let fd_server = match sock_type {
        libc::SOCK_STREAM => {
            let fd_accepted = tcp_connect_helper(fd_client, fd_server, libc::SOCK_NONBLOCK);
            unsafe { libc::close(fd_server) };
            fd_accepted
        }
        libc::SOCK_DGRAM => {
            udp_connect_helper(fd_client, fd_server, /* connect= */ true);
            fd_server
        }
        _ => unreachable!(),
    };

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_SNDBUF;

    let size = nix::sys::socket::getsockopt(fd_server, nix::sys::socket::sockopt::RcvBuf).unwrap();
    println!("Receive size: {:?}", size);

    test_utils::run_and_close_fds(&[fd_client, fd_server], || {
        let size = nix::sys::socket::getsockopt(fd_client, nix::sys::socket::sockopt::SndBuf).unwrap();
        println!("Before Before size: {:?}", size);

        //nix::sys::socket::setsockopt(fd_client, nix::sys::socket::sockopt::SndBuf, &2048).unwrap();
        nix::sys::socket::setsockopt(fd_server, nix::sys::socket::sockopt::RcvBuf, &(33000)).unwrap();
        let size = nix::sys::socket::getsockopt(fd_server, nix::sys::socket::sockopt::RcvBuf).unwrap();
        println!("Before Receive size: {:?}", size);
        
        let size = nix::sys::socket::getsockopt(fd_client, nix::sys::socket::sockopt::SndBuf).unwrap();
        println!("Before size: {:?}", size);

        let bytes = vec![0u8; 65000];

        {
            let rv = unsafe { libc::usleep(10000) };
            assert_eq!(rv, 0);
            let rv = unsafe { libc::usleep(10000) };
            assert_eq!(rv, 0);
        }

        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        {
            let rv = unsafe { libc::usleep(10000) };
            assert_eq!(rv, 0);
            let rv = unsafe { libc::usleep(10000) };
            assert_eq!(rv, 0);
        }
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        {
            let rv = unsafe { libc::usleep(10000) };
            assert_eq!(rv, 0);
            let rv = unsafe { libc::usleep(10000) };
            assert_eq!(rv, 0);
        }
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        let sent = nix::sys::socket::send(fd_client, &bytes, nix::sys::socket::MsgFlags::empty()).unwrap();
        
        let size = nix::sys::socket::getsockopt(fd_client, nix::sys::socket::sockopt::SndBuf).unwrap();
        println!("After size: {:?}", size);
        println!("Sent: {:?}", sent);

        let mut bytes2 = vec![0u8; 65000];
        let read = nix::sys::socket::recv(fd_server, &mut bytes2, nix::sys::socket::MsgFlags::empty()).unwrap();
        println!("Read: {:?}", read);
        let read = nix::sys::socket::recv(fd_server, &mut bytes2, nix::sys::socket::MsgFlags::empty()).unwrap();
        println!("Read: {:?}", read);
        let size = nix::sys::socket::getsockopt(fd_server, nix::sys::socket::sockopt::RcvBuf).unwrap();
        println!("After receive size: {:?}", size);
        
        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using the SO_RCVBUF option.
fn test_so_rcvbuf(domain: libc::c_int, sock_type: libc::c_int) -> Result<(), String> {
    let fd = unsafe { libc::socket(domain, sock_type, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_RCVBUF;
    let optvals = [0i32, 512, 1000, 2000, 8192, 16_384, -1];

    test_utils::run_and_close_fds(&[fd], || {
        for &optval in &optvals {
            // The man page (man 7 socket) is incorrect, and the actual minimum doubled value is
            // 2048 + some offset. See the definition of SOCK_MIN_RCVBUF in the kernel. We just
            // use 2048 and ignore the offset in these tests.
            let min_rcvbuf = 2048;

            bufsize_test_helper(fd, level, optname, optval, min_rcvbuf)?;
        }

        Ok(())
    })
}

fn bufsize_test_helper(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    optval: i32,
    min: i32,
) -> Result<(), String> {
    let optval = optval.to_ne_bytes();

    let mut initial_args = GetsockoptArguments::new(fd, level, optname, Some(vec![0u8; 4]));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut after_args = initial_args.clone();

    // get the value, set the value, and then get the value again
    check_getsockopt_call(&mut initial_args, &[])?;
    check_setsockopt_call(&mut set_args, &[])?;
    check_getsockopt_call(&mut after_args, &[])?;

    test_utils::result_assert_ne(
        &initial_args.optval.as_ref().unwrap()[..],
        &[0u8; 4],
        "The initial option was 0",
    )?;

    // convert the bytes to integers
    let set_optval = i32::from_ne_bytes(set_args.optval.as_ref().unwrap()[..].try_into().unwrap());
    let after_optval =
        i32::from_ne_bytes(after_args.optval.as_ref().unwrap()[..].try_into().unwrap());

    // linux always doubles the value when you set it (see man 7 socket)
    let set_optval = 2 * set_optval;

    // the value should be somewhere above the lower limit so that the program cannot set
    // very small sizes
    test_utils::result_assert(
        after_optval >= min,
        &format!(
            "Resulting value {} was expected to be larger than the min {}",
            after_optval, min
        ),
    )?;

    // if the value we set was above the lower limit, they should be equal
    if set_optval >= min {
        test_utils::result_assert_eq(
            after_optval,
            set_optval,
            "Resulting value was expected to be equal",
        )?;
    }

    Ok(())
}

/// Test getsockopt() and setsockopt() using the SO_ERROR option.
fn test_so_error(domain: libc::c_int, sock_type: libc::c_int) -> Result<(), String> {
    let fd = unsafe { libc::socket(domain, sock_type | libc::SOCK_NONBLOCK, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_SOCKET;
    let optname = libc::SO_ERROR;
    let optval = 0i32.to_ne_bytes();

    let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

    test_utils::run_and_close_fds(&[fd], || {
        check_getsockopt_call(&mut get_args, &[])?;
        check_setsockopt_call(&mut set_args, &[libc::ENOPROTOOPT])?;

        let returned_optval =
            i32::from_ne_bytes(get_args.optval.as_ref().unwrap()[..].try_into().unwrap());

        test_utils::result_assert_eq(returned_optval, 0, "Expected there to be no socket error")?;

        // We could try to trigger a socket error here and check to see that the value changed.
        // I tried to do this by making a non-blocking connection to localhost, but it didn't
        // seem to update the error either within Shadow or outside Shadow.

        Ok(())
    })
}

/// Test getsockopt() and setsockopt() using the TCP_INFO option.
fn test_tcp_info(domain: libc::c_int, sock_type: libc::c_int) -> Result<(), String> {
    let fd = unsafe { libc::socket(domain, sock_type, 0) };
    assert!(fd >= 0);

    let level = libc::SOL_TCP;
    let optname = libc::TCP_INFO;
    let optval = [0; 20];

    let mut get_args = GetsockoptArguments::new(fd, level, optname, Some(optval.into()));
    let mut set_args = SetsockoptArguments::new(fd, level, optname, Some(optval.into()));

    test_utils::run_and_close_fds(&[fd], || {
        let expected_errnos = if sock_type == libc::SOCK_STREAM {
            vec![]
        } else {
            vec![libc::EOPNOTSUPP]
        };
        check_getsockopt_call(&mut get_args, &expected_errnos)?;
        check_setsockopt_call(&mut set_args, &[libc::ENOPROTOOPT])?;

        // the libc package doesn't expose 'struct tcp_info' so if we wanted to look at the actual
        // values we'd have to use our own binding, but it's probably good enough here just to make
        // sure getsockopt() is returning something without an error

        Ok(())
    })
}

fn check_getsockopt_call(
    args: &mut GetsockoptArguments,
    expected_errnos: &[libc::c_int],
) -> Result<(), String> {
    // if the pointers will be non-null, make sure the length is not greater than the actual data size
    // so that we don't segfault
    if let (Some(optval), Some(optlen)) = (&args.optval, &args.optlen) {
        assert!(*optlen as usize <= optval.len());
    }

    let optval_ptr = match &mut args.optval {
        Some(slice) => slice.as_mut_ptr(),
        None => std::ptr::null_mut(),
    };

    test_utils::check_system_call!(
        move || unsafe {
            libc::getsockopt(
                args.fd,
                args.level,
                args.optname,
                optval_ptr as *mut core::ffi::c_void,
                args.optlen.as_mut_ptr(),
            )
        },
        expected_errnos,
    )?;

    Ok(())
}

fn check_setsockopt_call(
    args: &mut SetsockoptArguments,
    expected_errnos: &[libc::c_int],
) -> Result<(), String> {
    // if the pointers will be non-null, make sure the length is not greater than the actual data size
    // so that we don't segfault
    if let Some(optval) = &args.optval {
        assert!(args.optlen as usize <= optval.len());
    }

    let optval_ptr = match &args.optval {
        Some(slice) => slice.as_ptr(),
        None => std::ptr::null(),
    };

    test_utils::check_system_call!(
        move || unsafe {
            libc::setsockopt(
                args.fd,
                args.level,
                args.optname,
                optval_ptr as *mut core::ffi::c_void,
                args.optlen,
            )
        },
        expected_errnos,
    )?;

    Ok(())
}
