use atomic_refcell::AtomicRefCell;
use std::sync::Arc;

use crate::cshadow as c;
use crate::utility::event_queue::{EventQueue, EventSource, Handle};

use socket::{SocketFile, SocketFileRef, SocketFileRefMut};

#[macro_use]
macro_rules! impl_many {
    ($name:ident$(<$a:lifetime>)? { $code:item }) => {
        impl $name$(<$a>)? {
            $code
        }
    };
    ($name:ident$(<$a:lifetime>)? { $code:item $($more:item) + }) => {
        impl_many!($name$(<$a>)? { $code });
        impl_many!($name$(<$a>)? { $($more) + });
    };
    ($name:ident$(<$a:lifetime>)?, $($names:ident$(<$b:lifetime>)?),+ { $($more:item) + }) => {
        impl_many!($name$(<$a>)? { $($more) + });
        impl_many!($($names$(<$b>)?),+ { $($more) + });
    };
}

pub mod pipe;
pub mod socket;

/// A trait we can use as a compile-time check to make sure that an object is Send.
trait IsSend: Send {}

/// A trait we can use as a compile-time check to make sure that an object is Sync.
trait IsSync: Sync {}

/// A type that allows us to make a pointer Send + Sync since there is no way
/// to add these traits to the pointer itself.
#[derive(Clone, Copy)]
pub struct SyncSendPointer<T>(*mut T);

unsafe impl<T> Send for SyncSendPointer<T> {}
unsafe impl<T> Sync for SyncSendPointer<T> {}

impl<T> SyncSendPointer<T> {
    /// Get the pointer.
    pub fn ptr(&self) -> *mut T {
        self.0
    }

    /// Get a mutable reference to the pointer.
    pub fn ptr_ref(&mut self) -> &mut *mut T {
        &mut self.0
    }
}

#[derive(PartialEq)]
pub enum SyscallReturn {
    Success(i32),
    Error(nix::errno::Errno),
}

impl From<SyscallReturn> for c::SysCallReturn {
    fn from(syscall_return: SyscallReturn) -> Self {
        match syscall_return {
            SyscallReturn::Success(x) => Self {
                state: c::SysCallReturnState_SYSCALL_DONE,
                retval: c::SysCallReg { as_i64: x as i64 },
                cond: std::ptr::null_mut(),
            },
            SyscallReturn::Error(errno) => Self {
                state: c::SysCallReturnState_SYSCALL_DONE,
                retval: c::SysCallReg {
                    as_i64: -(errno as i64),
                },
                cond: std::ptr::null_mut(),
            },
        }
    }
}

bitflags::bitflags! {
    /// These are flags that can potentially be changed from the plugin (analagous to the Linux
    /// `filp->f_flags` status flags). Not all `O_` flags are valid here. For example file access
    /// mode flags (ex: `O_RDWR`) are stored elsewhere, and file creation flags (ex: `O_CREAT`)
    /// are not stored anywhere. Many of these can be represented in different ways, for example:
    /// `O_NONBLOCK`, `SOCK_NONBLOCK`, `EFD_NONBLOCK`, `GRND_NONBLOCK`, etc, and not all have the
    /// same value.
    pub struct FileFlags: libc::c_int {
        const NONBLOCK = libc::O_NONBLOCK;
        const APPEND = libc::O_APPEND;
        const ASYNC = libc::O_ASYNC;
        const DIRECT = libc::O_DIRECT;
        const NOATIME = libc::O_NOATIME;
    }
}

bitflags::bitflags! {
    /// These are flags that should generally not change (analagous to the Linux `filp->f_mode`).
    /// Since the plugin will never see these values and they're not exposed by the kernel, we
    /// don't match the kernel `FMODE_` values here.
    ///
    /// Examples: https://github.com/torvalds/linux/blob/master/include/linux/fs.h#L111
    pub struct FileMode: u32 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

bitflags::bitflags! {
    pub struct FileStatus: libc::c_int {
        /// Has been initialized and it is now OK to unblock any plugin waiting
        /// on a particular status.
        const ACTIVE = c::_Status_STATUS_DESCRIPTOR_ACTIVE;
        /// Can be read, i.e. there is data waiting for user.
        const READABLE = c::_Status_STATUS_DESCRIPTOR_READABLE;
        /// Can be written, i.e. there is available buffer space.
        const WRITABLE = c::_Status_STATUS_DESCRIPTOR_WRITABLE;
        /// User already called close.
        const CLOSED = c::_Status_STATUS_DESCRIPTOR_CLOSED;
        /// A wakeup operation occurred on a futex.
        const FUTEX_WAKEUP = c::_Status_STATUS_FUTEX_WAKEUP;
    }
}

impl From<c::Status> for FileStatus {
    fn from(status: c::Status) -> Self {
        // if any unexpected bits were present, then it's an error
        Self::from_bits(status).unwrap()
    }
}

impl From<FileStatus> for c::Status {
    fn from(status: FileStatus) -> Self {
        status.bits()
    }
}

#[derive(Clone)]
pub enum NewStatusListenerFilter {
    Never,
    OffToOn,
    OnToOff,
    Always,
}

/// A wrapper for a `*mut c::StatusListener` that increments its ref count when created,
/// and decrements when dropped.
struct LegacyStatusListener(SyncSendPointer<c::StatusListener>);

impl LegacyStatusListener {
    fn new(ptr: *mut c::StatusListener) -> Self {
        assert!(!ptr.is_null());
        unsafe { c::statuslistener_ref(ptr) };
        Self(SyncSendPointer(ptr))
    }

    fn ptr(&self) -> *mut c::StatusListener {
        self.0.ptr()
    }
}

impl Drop for LegacyStatusListener {
    fn drop(&mut self) {
        unsafe { c::statuslistener_unref(self.0.ptr()) };
    }
}

/// Stores event listener handles so that `c::StatusListener` objects can subscribe to events.
struct LegacyListenerHelper {
    handle_map: std::collections::HashMap<usize, Handle<(FileStatus, FileStatus)>>,
}

impl LegacyListenerHelper {
    fn new() -> Self {
        Self {
            handle_map: std::collections::HashMap::new(),
        }
    }

    fn add_listener(
        &mut self,
        ptr: *mut c::StatusListener,
        event_source: &mut EventSource<(FileStatus, FileStatus)>,
    ) {
        assert!(!ptr.is_null());

        // if it's already listening, don't add a second time
        if self.handle_map.contains_key(&(ptr as usize)) {
            return;
        }

        // this will ref the pointer and unref it when the closure is dropped
        let ptr_wrapper = LegacyStatusListener::new(ptr);

        let handle = event_source.add_listener(move |(status, changed), _event_queue| unsafe {
            c::statuslistener_onStatusChanged(ptr_wrapper.ptr(), status.into(), changed.into())
        });

        // use a usize as the key so we don't accidentally deref the pointer
        self.handle_map.insert(ptr as usize, handle);
    }

    fn remove_listener(&mut self, ptr: *mut c::StatusListener) {
        assert!(!ptr.is_null());
        self.handle_map.remove(&(ptr as usize));
    }
}

/// A specified event source that passes a status and the changed bits to the function, but only if
/// the monitored bits have changed and if the change the filter is satisfied.
struct StatusEventSource {
    inner: EventSource<(FileStatus, FileStatus)>,
    legacy_helper: LegacyListenerHelper,
}

impl StatusEventSource {
    pub fn new() -> Self {
        Self {
            inner: EventSource::new(),
            legacy_helper: LegacyListenerHelper::new(),
        }
    }

    pub fn add_listener(
        &mut self,
        monitoring: FileStatus,
        filter: NewStatusListenerFilter,
        notify_fn: impl Fn(FileStatus, FileStatus, &mut EventQueue) + Send + Sync + 'static,
    ) -> Handle<(FileStatus, FileStatus)> {
        self.inner
            .add_listener(move |(status, changed), event_queue| {
                // true if any of the bits we're monitoring have changed
                let flipped = monitoring.intersects(changed);

                // true if any of the bits we're monitoring are set
                let on = monitoring.intersects(status);

                let notify = match filter {
                    // at least one monitored bit is on, and at least one has changed
                    NewStatusListenerFilter::OffToOn => flipped && on,
                    // all monitored bits are off, and at least one has changed
                    NewStatusListenerFilter::OnToOff => flipped && !on,
                    // at least one monitored bit has changed
                    NewStatusListenerFilter::Always => flipped,
                    NewStatusListenerFilter::Never => false,
                };

                if !notify {
                    return;
                }

                (notify_fn)(status, changed, event_queue)
            })
    }

    pub fn add_legacy_listener(&mut self, ptr: *mut c::StatusListener) {
        self.legacy_helper.add_listener(ptr, &mut self.inner);
    }

    pub fn remove_legacy_listener(&mut self, ptr: *mut c::StatusListener) {
        self.legacy_helper.remove_listener(ptr);
    }

    pub fn notify_listeners(
        &mut self,
        status: FileStatus,
        changed: FileStatus,
        event_queue: &mut EventQueue,
    ) {
        self.inner.notify_listeners((status, changed), event_queue)
    }
}

/// Represents a POSIX description, or a Linux "struct file".
#[derive(Clone)]
pub enum PosixFile {
    Pipe(Arc<AtomicRefCell<pipe::PipeFile>>),
    Socket(SocketFile),
}

// will not compile if `PosixFile` is not Send + Sync
impl IsSend for PosixFile {}
impl IsSync for PosixFile {}

impl PosixFile {
    pub fn borrow(&self) -> PosixFileRef {
        match self {
            Self::Pipe(ref f) => PosixFileRef::Pipe(f.borrow()),
            Self::Socket(ref f) => PosixFileRef::Socket(f.borrow()),
        }
    }

    pub fn borrow_mut(&self) -> PosixFileRefMut {
        match self {
            Self::Pipe(ref f) => PosixFileRefMut::Pipe(f.borrow_mut()),
            Self::Socket(ref f) => PosixFileRefMut::Socket(f.borrow_mut()),
        }
    }

    pub fn canonical_handle(&self) -> usize {
        match self {
            Self::Pipe(f) => Arc::as_ptr(f) as usize,
            Self::Socket(f) => f.canonical_handle(),
        }
    }
}

pub enum PosixFileRef<'a> {
    Pipe(atomic_refcell::AtomicRef<'a, pipe::PipeFile>),
    Socket(SocketFileRef<'a>),
}

pub enum PosixFileRefMut<'a> {
    Pipe(atomic_refcell::AtomicRefMut<'a, pipe::PipeFile>),
    Socket(SocketFileRefMut<'a>),
}

impl_many!(PosixFileRefMut<'_>, PosixFileRef<'_> {
    pub fn status(&self) -> FileStatus {
        match self {
            Self::Pipe(ref f) => f.status(),
            Self::Socket(ref f) => f.status(),
        }
    }

    pub fn get_flags(&self) -> FileFlags {
        match self {
            Self::Pipe(f) => f.get_flags(),
            Self::Socket(f) => f.get_flags(),
        }
    }
});

impl PosixFileRefMut<'_> {
    pub fn read(&mut self, bytes: &mut [u8], event_queue: &mut EventQueue) -> SyscallReturn {
        match self {
            Self::Pipe(ref mut f) => f.read(bytes, event_queue),
            Self::Socket(ref mut f) => {
                panic!("Should have called recvfrom() on the socket instead")
            }
        }
    }

    pub fn write(&mut self, bytes: &[u8], event_queue: &mut EventQueue) -> SyscallReturn {
        match self {
            Self::Pipe(ref mut f) => f.write(bytes, event_queue),
            Self::Socket(ref mut f) => panic!("Should have called sendto() on the socket instead"),
        }
    }

    pub fn close(&mut self, event_queue: &mut EventQueue) -> SyscallReturn {
        match self {
            Self::Pipe(ref mut f) => f.close(event_queue),
            Self::Socket(ref mut f) => f.close(event_queue),
        }
    }

    pub fn set_flags(&mut self, flags: FileFlags) {
        match self {
            Self::Pipe(f) => f.set_flags(flags),
            Self::Socket(f) => f.set_flags(flags),
        }
    }

    pub fn add_legacy_listener(&mut self, ptr: *mut c::StatusListener) {
        match self {
            Self::Pipe(f) => f.add_legacy_listener(ptr),
            Self::Socket(f) => f.add_legacy_listener(ptr),
        }
    }

    pub fn remove_legacy_listener(&mut self, ptr: *mut c::StatusListener) {
        match self {
            Self::Pipe(f) => f.remove_legacy_listener(ptr),
            Self::Socket(f) => f.remove_legacy_listener(ptr),
        }
    }
}

/*
pub trait Things {
    fn status(&self) -> FileStatus;
}

pub trait MutThings {
    fn read(&mut self, bytes: &mut [u8], event_queue: &mut EventQueue) -> SyscallReturn;
    fn write(&mut self, bytes: &[u8], event_queue: &mut EventQueue) -> SyscallReturn;
}

#[deny(unconditional_recursion)]
impl Things for PosixFileRef<'_> {
    fn status(&self) -> FileStatus {
        self.status()
    }
}

#[deny(unconditional_recursion)]
impl Things for PosixFileRefMut<'_> {
    fn status(&self) -> FileStatus {
        self.status()
    }
}

#[deny(unconditional_recursion)]
impl MutThings for PosixFileRefMut<'_> {
    fn read(&mut self, bytes: &mut [u8], event_queue: &mut EventQueue) -> SyscallReturn {
        self.read(bytes, event_queue)
    }

    fn write(&mut self, bytes: &[u8], event_queue: &mut EventQueue) -> SyscallReturn {
        self.write(bytes, event_queue)
    }
}
*/

//pub enum Test<'a> {
//    Pipe(&'a pipe::PipeFile),
//}

/*
pub fn my_func(f: PosixFile) {
    // can pattern match at the top level if you need the Arc
    if let PosixFile::Pipe(ref p) = f {
        p.borrow().status();
    }

    let mut f = f.borrow_mut();

    // can call functions directly on the borrowed reference
    let buf = [0u8; 10];
    EventQueue::queue_and_run(|event_queue| {
        f.write(&buf, event_queue);
    });

    // can pattern match on the borrowed reference
    if let PosixFileRefMut::Pipe(p) = f {
        p.status();
    }
}

pub fn test(f: PosixFile) -> FileStatus {
    let mut f = f.borrow_mut();

    let buf = [0u8; 10];
    f.write(&buf, &mut EventQueue::new());

    if let PosixFileRefMut::Pipe(p) = f {
        p.status()
    } else {
        unreachable!()
    }
}
*/

bitflags::bitflags! {
    // Linux only supports a single descriptor flag:
    // https://www.gnu.org/software/libc/manual/html_node/Descriptor-Flags.html
    pub struct DescriptorFlags: u32 {
        const CLOEXEC = libc::FD_CLOEXEC as u32;
    }
}

#[derive(Clone)]
pub struct Descriptor {
    file: PosixFile,
    flags: DescriptorFlags,
    count: Arc<()>,
}

impl Descriptor {
    pub fn new(file: PosixFile) -> Self {
        Self {
            file,
            flags: DescriptorFlags::empty(),
            count: Arc::new(()),
        }
    }

    pub fn get_file(&self) -> &PosixFile {
        &self.file
    }

    pub fn get_flags(&self) -> DescriptorFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: DescriptorFlags) {
        self.flags = flags;
    }

    pub fn get_fd_count(&self) -> usize {
        Arc::<()>::strong_count(&self.count)
    }
}

// don't implement copy or clone without considering the legacy descriptor's ref count
pub enum CompatDescriptor {
    New(Descriptor),
    Legacy(SyncSendPointer<c::LegacyDescriptor>),
}

// will not compile if `CompatDescriptor` is not Send + Sync
impl IsSend for CompatDescriptor {}
impl IsSync for CompatDescriptor {}

impl Drop for CompatDescriptor {
    fn drop(&mut self) {
        if let CompatDescriptor::Legacy(d) = self {
            // unref the legacy descriptor object
            unsafe { c::descriptor_unref(d.ptr() as *mut core::ffi::c_void) };
        }
    }
}

mod export {
    use super::*;

    /// The new compat descriptor takes ownership of the reference to the legacy descriptor and
    /// does not increment its ref count, but will decrement the ref count when this compat
    /// descriptor is freed/dropped.
    #[no_mangle]
    pub extern "C" fn compatdescriptor_fromLegacy(
        legacy_descriptor: *mut c::LegacyDescriptor,
    ) -> *mut CompatDescriptor {
        assert!(!legacy_descriptor.is_null());

        let descriptor = CompatDescriptor::Legacy(SyncSendPointer(legacy_descriptor));
        Box::into_raw(Box::new(descriptor))
    }

    /// If the compat descriptor is a legacy descriptor, returns a pointer to the legacy
    /// descriptor object. Otherwise returns NULL. The legacy descriptor's ref count is not
    /// modified, so the pointer must not outlive the lifetime of the compat descriptor.
    #[no_mangle]
    pub extern "C" fn compatdescriptor_asLegacy(
        descriptor: *const CompatDescriptor,
    ) -> *mut c::LegacyDescriptor {
        assert!(!descriptor.is_null());

        let descriptor = unsafe { &*descriptor };

        if let CompatDescriptor::Legacy(d) = descriptor {
            d.ptr()
        } else {
            std::ptr::null_mut()
        }
    }

    /// When the compat descriptor is freed/dropped, it will decrement the legacy descriptor's
    /// ref count.
    #[no_mangle]
    pub extern "C" fn compatdescriptor_free(descriptor: *mut CompatDescriptor) {
        if descriptor.is_null() {
            return;
        }

        let descriptor = unsafe { &mut *descriptor };
        unsafe { Box::from_raw(descriptor) };
    }

    /// This is a no-op for non-legacy descriptors.
    #[no_mangle]
    pub extern "C" fn compatdescriptor_setHandle(
        descriptor: *mut CompatDescriptor,
        handle: libc::c_int,
    ) {
        assert!(!descriptor.is_null());

        let descriptor = unsafe { &mut *descriptor };

        if let CompatDescriptor::Legacy(d) = descriptor {
            unsafe { c::descriptor_setHandle(d.ptr(), handle) }
        }

        // new descriptor types don't store their file handle, so do nothing
    }

    /// If the compat descriptor is a new descriptor, returns a pointer to the reference-counted
    /// posix file object. Otherwise returns NULL. The posix file object's ref count is not
    /// modified, so the pointer must not outlive the lifetime of the compat descriptor.
    #[no_mangle]
    pub extern "C" fn compatdescriptor_borrowPosixFile(
        descriptor: *mut CompatDescriptor,
    ) -> *const PosixFile {
        assert!(!descriptor.is_null());

        let descriptor = unsafe { &mut *descriptor };

        match descriptor {
            CompatDescriptor::Legacy(_) => std::ptr::null(),
            CompatDescriptor::New(d) => d.get_file(),
        }
    }

    /// If the compat descriptor is a new descriptor, returns a pointer to the reference-counted
    /// posix file object. Otherwise returns NULL. The posix file object's ref count is
    /// incremented, so the pointer must always later be passed to `posixfile_drop()`, otherwise
    /// the memory will leak.
    #[no_mangle]
    pub extern "C" fn compatdescriptor_newRefPosixFile(
        descriptor: *mut CompatDescriptor,
    ) -> *const PosixFile {
        assert!(!descriptor.is_null());

        let descriptor = unsafe { &mut *descriptor };

        match descriptor {
            CompatDescriptor::Legacy(_) => std::ptr::null(),
            CompatDescriptor::New(d) => Box::into_raw(Box::new(d.get_file().clone())),
        }
    }

    /// Decrement the ref count of the posix file object. The pointer must not be used after
    /// calling this function.
    #[no_mangle]
    pub extern "C" fn posixfile_drop(file: *const PosixFile) {
        assert!(!file.is_null());

        unsafe { Box::from_raw(file as *mut PosixFile) };
    }

    /// Get the status of the posix file object.
    #[allow(unused_variables)]
    #[no_mangle]
    pub extern "C" fn posixfile_getStatus(file: *const PosixFile) -> c::Status {
        assert!(!file.is_null());

        let file = unsafe { &*file };
        file.borrow().status().into()
    }

    /// Add a status listener to the posix file object. This will increment the status
    /// listener's ref count, and will decrement the ref count when this status listener is
    /// removed or when the posix file is freed/dropped.
    #[no_mangle]
    pub extern "C" fn posixfile_addListener(
        file: *const PosixFile,
        listener: *mut c::StatusListener,
    ) {
        assert!(!file.is_null());
        assert!(!listener.is_null());

        let file = unsafe { &*file };
        file.borrow_mut().add_legacy_listener(listener);
    }

    /// Remove a listener from the posix file object.
    #[no_mangle]
    pub extern "C" fn posixfile_removeListener(
        file: *const PosixFile,
        listener: *mut c::StatusListener,
    ) {
        assert!(!file.is_null());
        assert!(!listener.is_null());

        let file = unsafe { &*file };
        file.borrow_mut().remove_legacy_listener(listener);
    }

    /// Get the canonical handle for a posix file object. Two posix file objects refer to the same
    /// underlying data if their handles are equal.
    #[no_mangle]
    pub extern "C" fn posixfile_getCanonicalHandle(file: *const PosixFile) -> libc::uintptr_t {
        assert!(!file.is_null());

        let file = unsafe { &*file };
        file.canonical_handle()
    }
}
