/*
 * The Shadow Simulator
 * See LICENSE for licensing information
 */
// clang-format off


#ifndef main_opaque_bindings_h
#define main_opaque_bindings_h

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

// A queue of byte chunks.
typedef struct ByteQueue ByteQueue;

typedef struct CompatDescriptor CompatDescriptor;

// Manages the address-space for a plugin process.
//
// The MemoryManager's primary purpose is to make plugin process's memory directly accessible to
// Shadow. It does this by tracking what regions of program memory in the plugin are mapped to
// what (analagous to /proc/<pid>/maps), and *remapping* parts of the plugin's address space into
// a shared memory-file, which is also mapped into Shadow.
//
// Shadow provides several methods for allowing Shadow to access the plugin's memory, such as
// `get_readable_ptr`. If the corresponding region of plugin memory is mapped into the shared
// memory file, the corresponding Shadow pointer is returned. If not, then, it'll fall back to
// (generally slower) Thread APIs.
//
// For the MemoryManager to maintain consistent state, and to remap regions of memory it knows how
// to remap, Shadow must delegate handling of mman-related syscalls (such as `mmap`) to the
// MemoryManager via its `handle_*` methods.
typedef struct MemoryManager MemoryManager;

// Represents a POSIX description, or a Linux "struct file".
typedef struct PosixFile PosixFile;

typedef struct SocketFile SocketFile;

#endif /* main_opaque_bindings_h */
