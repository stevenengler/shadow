/*
 * The Shadow Simulator
 * Copyright (c) 2010-2011, Rob Jansen
 * See LICENSE for licensing information
 */
#include "main/host/process.h"

#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

#include "glib/gprintf.h"
#include "lib/logger/logger.h"
#include "main/bindings/c/bindings.h"
#include "main/core/support/config_handlers.h"
#include "main/core/support/definitions.h"
#include "main/core/worker.h"
#include "main/host/descriptor/compat_socket.h"
#include "main/host/descriptor/descriptor.h"
#include "main/host/descriptor/descriptor_types.h"
#include "main/host/descriptor/regular_file.h"
#include "main/host/descriptor/socket.h"
#include "main/host/descriptor/tcp.h"
#include "main/host/descriptor/timerfd.h"
#include "main/host/managed_thread.h"
#include "main/host/process.h"
#include "main/host/shimipc.h"
#include "main/host/syscall_condition.h"
#include "main/host/syscall_types.h"
#include "main/host/thread.h"
#include "main/host/tracker.h"
#include "main/routing/address.h"
#include "main/routing/dns.h"
#include "main/utility/utility.h"

static void _process_check(Process* proc);

struct _Process {
    /* Pointer to the RustProcess that owns this Process */
    const RustProcess* rustProcess;

#ifdef USE_PERF_TIMERS
    /* timer that tracks the amount of CPU time we spend on plugin execution and processing */
    GTimer* cpuDelayTimer;
    gdouble totalRunTime;
#endif

    // int thread_id -> Thread*.
    GHashTable* threads;

    /* Native pid of the process */
    pid_t nativePid;

    // Pending MemoryReaders and MemoryWriters
    ProcessMemoryRefMut_u8* memoryMutRef;
    GArray* memoryRefs;

    MAGIC_DECLARE;
};

static void _unref_thread_cb(gpointer data);

static const Host* _host(Process* proc) {
    const Host* host = worker_getCurrentHost();
    utility_debugAssert(host_getID(host) == process_getHostId(proc));
    return host;
}

static Thread* _process_threadLeader(Process* proc) {
    // "main" thread is the one where pid==tid.
    return g_hash_table_lookup(proc->threads, GUINT_TO_POINTER(process_getProcessID(proc)));
}

const ShimShmemProcess* process_getSharedMem(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_getSharedMem(proc->rustProcess);
}

// FIXME: still needed? Time is now updated more granularly in the Thread code
// when xferring control to/from shim.
static void _process_setSharedTime(Process* proc) {
    const Host* host = _host(proc);
    shimshmem_setMaxRunaheadTime(host_getShimShmemLock(host), worker_maxEventRunaheadTime(host));
    shimshmem_setEmulatedTime(host_getSharedMem(host), worker_getCurrentEmulatedTime());
}

const gchar* process_getName(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_getName(proc->rustProcess);
}

StraceFmtMode process_straceLoggingMode(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_straceLoggingMode(proc->rustProcess);
}

int process_getStraceFd(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_straceFd(proc->rustProcess);
}

const gchar* process_getPluginName(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_getPluginName(proc->rustProcess);
}

const char* process_getWorkingDir(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_getWorkingDir(proc->rustProcess);
}

pid_t process_getProcessID(Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_getProcessID(proc->rustProcess);
}

pid_t process_getNativePid(const Process* proc) {
    MAGIC_ASSERT(proc);
    return proc->nativePid;
}

static void _process_reapThread(Process* process, Thread* thread) {
    utility_debugAssert(!thread_isRunning(thread));

    // If the `clear_child_tid` attribute on the thread is set, and there are
    // any other threads left alive in the process, perform a futex wake on
    // that address. This mechanism is typically used in `pthread_join` etc.
    // See `set_tid_address(2)`.
    PluginVirtualPtr clear_child_tid_pvp = thread_getTidAddress(thread);
    if (clear_child_tid_pvp.val && g_hash_table_size(process->threads) > 1 && !_process_isExiting(process->rustProcess)) {
        // Verify thread is really dead. This *should* no longer be needed, but doesn't
        // hurt to defensively do anyway, since waking the futex before the thread has
        // actually exited can (and has) led to difficult-to-track-down bugs.
        while (1) {
            pid_t pid = thread_getNativePid(thread);
            pid_t tid = thread_getNativeTid(thread);
            int rv = (int)syscall(SYS_tgkill, pid, tid, 0);
            if (rv == -1 && errno == ESRCH) {
                trace("Thread is done exiting, proceeding with cleanup");
                break;
            } else if (rv != 0) {
                error("Unexpected tgkill rv:%d errno:%s", rv, g_strerror(errno));
                break;
            } else if (pid == tid) {
                trace("%d.%d can still receive signals", pid, tid);

                // Thread leader could be in a zombie state waiting for the other threads to exit.
                gchar* filename = g_strdup_printf("/proc/%d/stat", pid);
                gchar* contents = NULL;
                gboolean rv = g_file_get_contents(filename, &contents, NULL, NULL);
                g_free(filename);
                if (!rv) {
                    trace("tgl %d is fully dead", pid);
                    break;
                }
                bool is_zombie = strstr(contents, ") Z") != NULL;
                g_free(contents);
                if (is_zombie) {
                    trace("tgl %d is a zombie", pid);
                    break;
                }
                // Still alive and in a non-zombie state; continue
            }
            debug("%d.%d still running; waiting for it to exit", pid, tid);
            sched_yield();
            // Check again
        }

        pid_t* clear_child_tid =
            process_getWriteablePtr(process, clear_child_tid_pvp, sizeof(pid_t*));
        if (!clear_child_tid) {
            // We *might* end up getting here (or failing even earlier) if we end up having to use
            // thread_getWriteablePtr (i.e. because the address isn't shared in the
            // MemoryManager), since the native thread (and maybe the whole
            // process) is no longer alive. If so, the most straightforward
            // fix might be to extend the MemoryManager to include the region
            // containing the tid pointer in this case.
            //
            // Alternatively we could try to use a still-living thread (if any)
            // to do the memory write, and just skip if there are no more
            // living threads in the process. Probably better to avoid that
            // complexity if we can, though.
            utility_panic("Couldn't clear child tid; See code comments.");
            abort();
        }

        *clear_child_tid = 0;

        // *don't* flush here. The write may not succeed if the current thread
        // is dead. Leave it pending for the next thread in the process to
        // flush.

        FutexTable* ftable = host_getFutexTable(_host(process));
        utility_debugAssert(ftable);
        Futex* futex =
            futextable_get(ftable, process_getPhysicalAddress(process, clear_child_tid_pvp));
        if (futex) {
            futex_wake(futex, 1);
        }
    }
}

static void _process_handleProcessExit(Process* proc) {
    trace("handleProcessExit");
    utility_debugAssert(!process_isRunning(proc));

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, proc->threads);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        Thread* thread = value;
        thread_handleProcessExit(thread);
        utility_debugAssert(!thread_isRunning(thread));
        _process_reapThread(proc, thread);

        // Must be last, since it unrefs the thread.
        g_hash_table_iter_remove(&iter);
    }

    _process_check(proc);
}

static void _process_terminate(Process* proc) {
    if (!process_hasStarted(proc)) {
        trace("Never started");
        return;
    }

    if (!process_isRunning(proc)) {
        trace("Already dead");
        // We should have already cleaned up.
        utility_debugAssert(_process_didLogReturnCode(proc->rustProcess));
        return;
    }
    trace("Terminating");
    _process_setWasKilledByShadow(proc->rustProcess);

    if (kill(proc->nativePid, SIGKILL)) {
        warning("kill(pid=%d) error %d: %s", proc->nativePid, errno, g_strerror(errno));
    }
    process_markAsExiting(proc);
    _process_handleProcessExit(proc);
}

#ifdef USE_PERF_TIMERS
static void _process_handleTimerResult(Process* proc, gdouble elapsedTimeSec) {
    uint64_t delayNanos = elapsedTimeSec * 1000000000ull;
    const Host* host = _host(proc);
    host_addDelayNanos(host, delayNanos);
    Tracker* tracker = host_getTracker(host);
    if (tracker != NULL) {
        tracker_addProcessingTimeNanos(tracker, delayNanos);
    }
    proc->totalRunTime += elapsedTimeSec;
}
#endif

static void _process_getAndLogReturnCode(Process* proc) {
    if (_process_didLogReturnCode(proc->rustProcess)) {
        return;
    }

    if (!process_hasStarted(proc)) {
        error("Process '%s' with a start time of %" G_GUINT64_FORMAT " did not start",
              process_getName(proc),
              emutime_sub_emutime(
                  _process_getStartTime(proc->rustProcess), EMUTIME_SIMULATION_START));
        return;
    }

    // Return an error if we can't get real exit code.
    int returnCode = EXIT_FAILURE;

    int wstatus = 0;
    int rv = waitpid(proc->nativePid, &wstatus, __WALL);
    if (rv < 0) {
        // Getting here is a bug, but since the process is exiting anyway
        // not serious enough to merit `error`ing out.
        warning("waitpid: %s", g_strerror(errno));
    } else if (rv != proc->nativePid) {
        warning("waitpid returned %d instead of the requested %d", rv, proc->nativePid);
    } else {
        if (WIFEXITED(wstatus)) {
            returnCode = WEXITSTATUS(wstatus);
        } else if (WIFSIGNALED(wstatus)) {
            returnCode = return_code_for_signal(WTERMSIG(wstatus));
        } else {
            warning("Couldn't get exit status");
        }
    }

    _process_setReturnCode(proc->rustProcess, returnCode);

    GString* mainResultString = g_string_new(NULL);
    g_string_printf(mainResultString, "process '%s'", process_getName(proc));
    if (_process_wasKilledByShadow(proc->rustProcess)) {
        g_string_append_printf(mainResultString, " killed by Shadow");
    } else {
        g_string_append_printf(mainResultString, " exited with code %d", returnCode);
        if (returnCode == 0) {
            g_string_append_printf(mainResultString, " (success)");
        } else {
            g_string_append_printf(mainResultString, " (error)");
        }
    }

    char fileName[4000];
    _process_outputFileName(
        proc->rustProcess, _host(proc), "exitcode", &fileName[0], sizeof(fileName));
    FILE* exitcodeFile = fopen(fileName, "we");

    if (exitcodeFile != NULL) {
        if (_process_wasKilledByShadow(proc->rustProcess)) {
            // Process never died during the simulation; shadow chose to kill it;
            // typically because the simulation end time was reached.
            // Write out an empty exitcode file.
        } else {
            fprintf(exitcodeFile, "%d", returnCode);
        }
        fclose(exitcodeFile);
    } else {
        warning("Could not open '%s' for writing: %s", mainResultString->str, strerror(errno));
    }

    // if there was no error or was intentionally killed
    // TODO: once we've implemented clean shutdown via SIGTERM,
    //       treat death by SIGKILL as a plugin error
    if (returnCode == 0 || _process_wasKilledByShadow(proc->rustProcess)) {
        info("%s", mainResultString->str);
    } else {
        warning("%s", mainResultString->str);
        worker_incrementPluginErrors();
    }

    g_string_free(mainResultString, TRUE);
}

pid_t process_findNativeTID(Process* proc, pid_t virtualPID, pid_t virtualTID) {
    MAGIC_ASSERT(proc);

    Thread* thread = NULL;

    pid_t pid = process_getProcessID(proc);
    if (virtualPID > 0 && virtualTID > 0) {
        // Both PID and TID must match
        if (pid == virtualPID) {
            thread = g_hash_table_lookup(proc->threads, GINT_TO_POINTER(virtualTID));
        }
    } else if (virtualPID > 0) {
        // Get the TID of the main thread if the PID matches
        if (pid == virtualPID) {
            thread = _process_threadLeader(proc);
        }
    } else if (virtualTID > 0) {
        // Get the TID of any thread that matches, ignoring PID
        thread = g_hash_table_lookup(proc->threads, GINT_TO_POINTER(virtualTID));
    }

    if (thread != NULL) {
        return thread_getNativeTid(thread);
    } else {
        return 0; // not found
    }
}

static void _process_check(Process* proc) {
    MAGIC_ASSERT(proc);

    if (process_isRunning(proc) || !process_hasStarted(proc)) {
        return;
    }

    info("process '%s' has completed or is otherwise no longer running", process_getName(proc));
    _process_getAndLogReturnCode(proc);
#ifdef USE_PERF_TIMERS
    info(
        "total runtime for process '%s' was %f seconds", process_getName(proc), proc->totalRunTime);
#endif

    utility_alwaysAssert(proc->rustProcess);
    _process_descriptorTableShutdownHelper(proc->rustProcess);
    _process_descriptorTableRemoveAndCloseAll(proc->rustProcess);
}

static void _process_check_thread(Process* proc, Thread* thread) {
    if (thread_isRunning(thread)) {
        debug("thread %d in process '%s' still running, but blocked", thread_getID(thread),
              process_getName(proc));
        return;
    }
    int returnCode = thread_getReturnCode(thread);
    debug("thread %d in process '%s' exited with code %d", thread_getID(thread),
          process_getName(proc), returnCode);
    _process_reapThread(proc, thread);
    g_hash_table_remove(proc->threads, GUINT_TO_POINTER(thread_getID(thread)));
    _process_check(proc);
}

void process_start(Process* proc, const char* const* argv, const char* const* envv_in) {
    MAGIC_ASSERT(proc);

    /* we shouldn't already be running */
    utility_alwaysAssert(!process_isRunning(proc));

    // tid of first thread of a process is equal to the pid.
    int tid = process_getProcessID(proc);
    Thread* mainThread = thread_new(_host(proc), proc, tid);

    g_hash_table_insert(proc->threads, GUINT_TO_POINTER(tid), mainThread);

    info("starting process '%s'", process_getName(proc));

    /* now we will execute in the pth/plugin context, so we need to load the state */
    worker_setActiveProcess(proc);
    worker_setActiveThread(mainThread);

#ifdef USE_PERF_TIMERS
    /* time how long we execute the program */
    g_timer_start(proc->cpuDelayTimer);
#endif

    gchar** envv = g_strdupv((gchar**)envv_in);

    /* Add shared mem block of first thread to env */
    {
        ShMemBlockSerialized sharedMemBlockSerial =
            shmemallocator_globalBlockSerialize(thread_getShMBlock(mainThread));

        char sharedMemBlockBuf[SHD_SHMEM_BLOCK_SERIALIZED_MAX_STRLEN] = {0};
        shmemblockserialized_toString(&sharedMemBlockSerial, sharedMemBlockBuf);

        /* append to the env */
        envv = g_environ_setenv(envv, "SHADOW_SHM_THREAD_BLK", sharedMemBlockBuf, TRUE);
    }

    _process_setSharedTime(proc);
    /* exec the process */
    thread_run(mainThread, _process_getPluginPath(proc->rustProcess), argv,
               (const char* const*)envv, process_getWorkingDir(proc));
    g_strfreev(envv);
    proc->nativePid = thread_getNativePid(mainThread);
    _process_createMemoryManager(proc->rustProcess, proc->nativePid);

#ifdef USE_PERF_TIMERS
    gdouble elapsed = g_timer_elapsed(proc->cpuDelayTimer, NULL);
    _process_handleTimerResult(proc, elapsed);
    info("process '%s' started in %f seconds", process_getName(proc), elapsed);
#else
    info("process '%s' started", process_getName(proc));
#endif

    worker_setActiveProcess(NULL);
    worker_setActiveThread(NULL);

    if (_process_shouldPauseForDebugging(proc->rustProcess)) {
        // will block until logger output has been flushed
        // there is a race condition where other threads may log between the fprintf() and raise()
        // below, but it should be rare
        logger_flush(logger_getDefault());

        // print with hopefully a single syscall to avoid splitting these messages (fprintf should
        // not buffer stderr output)
        fprintf(stderr,
                "** Pausing with SIGTSTP to enable debugger attachment to managed process '%s' "
                "(pid %d)\n"
                "** If running Shadow under Bash, resume Shadow by pressing Ctrl-Z to background "
                "this task and then typing \"fg\".\n"
                "** (If you wish to kill Shadow, type \"kill %%%%\" instead.)\n"
                "** If running Shadow under GDB, resume Shadow by typing \"signal SIGCONT\".\n",
                process_getName(proc), proc->nativePid);

        raise(SIGTSTP);
    }

    /* call main and run until blocked */
    process_continue(proc, mainThread);
}

static void _start_thread_task(const Host* host, gpointer callbackObject,
                               gpointer callbackArgument) {
    pid_t pid = GPOINTER_TO_INT(callbackObject);
    Process* process = host_getProcess(host, pid);
    if (!process) {
        debug("Process %d no longer exists", pid);
        return;
    }

    Thread* thread = callbackArgument;
    process_continue(process, thread);
}

static void _unref_thread_cb(gpointer data) {
    Thread* thread = data;
    thread_unref(thread);
}

void process_addThread(Process* proc, Thread* thread) {
    MAGIC_ASSERT(proc);
    g_hash_table_insert(proc->threads, GUINT_TO_POINTER(thread_getID(thread)), thread);

    // Schedule thread to start.
    thread_ref(thread);
    const Host* host = _host(proc);
    TaskRef* task = taskref_new_bound(host_getID(host), _start_thread_task,
                                      GINT_TO_POINTER(process_getProcessID(proc)), thread, NULL,
                                      _unref_thread_cb);
    host_scheduleTaskWithDelay(host, task, 0);
    taskref_drop(task);
}

Thread* process_getThread(Process* proc, pid_t virtualTID) {
    return g_hash_table_lookup(proc->threads, GINT_TO_POINTER(virtualTID));
}

void process_markAsExiting(Process* proc) {
    MAGIC_ASSERT(proc);
    _process_markAsExiting(proc->rustProcess);
}

void process_continue(Process* proc, Thread* thread) {
    MAGIC_ASSERT(proc);
    trace("Continuing thread %d in process %d", thread_getID(thread), process_getProcessID(proc));

    /* if we are not running, no need to notify anyone */
    if(!process_isRunning(proc)) {
        return;
    }

    debug(
        "switching to thread controller to continue executing process '%s'", process_getName(proc));

    worker_setActiveProcess(proc);
    worker_setActiveThread(thread);

#ifdef USE_PERF_TIMERS
    /* time how long we execute the program */
    g_timer_start(proc->cpuDelayTimer);
#endif

    _process_setSharedTime(proc);

    shimshmem_resetUnappliedCpuLatency(host_getShimShmemLock(_host(proc)));
    thread_resume(thread);

#ifdef USE_PERF_TIMERS
    gdouble elapsed = g_timer_elapsed(proc->cpuDelayTimer, NULL);
    _process_handleTimerResult(proc, elapsed);
    info("process '%s' ran for %f seconds", process_getName(proc), elapsed);
#else
    debug("process '%s' done continuing", process_getName(proc));
#endif

    if (_process_isExiting(proc->rustProcess)) {
        // If the whole process is already exiting, skip to cleaning up the
        // whole process exit; normal thread cleanup would likely fail.
        _process_handleProcessExit(proc);
    } else {
        _process_check_thread(proc, thread);
    }

    worker_setActiveProcess(NULL);
    worker_setActiveThread(NULL);
}

void process_stop(Process* proc) {
    MAGIC_ASSERT(proc);

    info("terminating process '%s'", process_getName(proc));

    worker_setActiveProcess(proc);

#ifdef USE_PERF_TIMERS
    /* time how long we execute the program */
    g_timer_start(proc->cpuDelayTimer);
#endif

    _process_terminate(proc);

#ifdef USE_PERF_TIMERS
    gdouble elapsed = g_timer_elapsed(proc->cpuDelayTimer, NULL);
    _process_handleTimerResult(proc, elapsed);
#endif

    worker_setActiveProcess(NULL);

#ifdef USE_PERF_TIMERS
    info("process '%s' stopped in %f seconds", process_getName(proc), elapsed);
#else
    info("process '%s' stopped", process_getName(proc));
#endif

    _process_check(proc);
}

void process_detachPlugin(gpointer procptr, gpointer nothing) {
    // TODO: Remove
}

gboolean process_hasStarted(Process* proc) {
    MAGIC_ASSERT(proc);
    return proc->nativePid > 0;
}

gboolean process_isRunning(Process* proc) {
    MAGIC_ASSERT(proc);
    return !_process_isExiting(proc->rustProcess) && g_hash_table_size(proc->threads) > 0;
}

static void _thread_gpointer_unref(gpointer data) { thread_unref(data); }

void process_initSiginfoForAlarm(siginfo_t* siginfo, int overrun) {
    *siginfo = (siginfo_t){
        .si_signo = SIGALRM,
        .si_code = SI_TIMER,
        .si_overrun = overrun,
    };
}

Process* process_new(const RustProcess* rustProcess, const Host* host, pid_t processID,
                     bool pause_for_debugging) {
    Process* proc = g_new0(Process, 1);
    MAGIC_INIT(proc);

#ifdef USE_PERF_TIMERS
    proc->cpuDelayTimer = g_timer_new();
#endif

    proc->threads =
        g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, _thread_gpointer_unref);

    proc->memoryMutRef = NULL;
    proc->memoryRefs = g_array_new(FALSE, FALSE, sizeof(ProcessMemoryRef_u8*));

    proc->rustProcess = rustProcess;

    worker_count_allocation(Process);

    return proc;
}

void process_setRustProcess(Process* proc, const RustProcess* rproc) {
    MAGIC_ASSERT(proc);
    utility_alwaysAssert(proc->rustProcess == NULL);
    proc->rustProcess = rproc;
}

const RustProcess* process_getRustProcess(Process* proc) {
    MAGIC_ASSERT(proc);
    utility_alwaysAssert(proc->rustProcess);
    return proc->rustProcess;
}

void process_free(Process* proc) {
    MAGIC_ASSERT(proc);

    process_freePtrsWithoutFlushing(proc);
    g_array_free(proc->memoryRefs, true);

    // FIXME: call to _process_terminate removed.
    // We can't call it here, since the Rust Process inside the RustProcess (RootededRefCell<Process>)
    // has been extracted, invalidating proc->rustProcess.
    //
    // We *shouldn't* need to call _process_terminate here, since Host::free_all_applications
    // already explicitly stops all processes before freeing them, but once the relevant code is
    // all in Rust we should ensure the process is terminated in our Drop implementation.

    if (proc->threads) {
        g_hash_table_destroy(proc->threads);
        proc->threads = NULL;
    }

#ifdef USE_PERF_TIMERS
    g_timer_destroy(proc->cpuDelayTimer);
#endif

    worker_count_deallocation(Process);

    MAGIC_CLEAR(proc);
    g_free(proc);
}

HostId process_getHostId(const Process* proc) {
    MAGIC_ASSERT(proc);
    return _process_getHostId(proc->rustProcess);
}

PluginPhysicalPtr process_getPhysicalAddress(Process* proc, PluginVirtualPtr vPtr) {
    // We currently don't keep a true system-wide virtual <-> physical address
    // mapping. Instead we simply assume that no shadow processes map the same
    // underlying physical memory, and that therefore (pid, virtual address)
    // uniquely defines a physical address.
    //
    // If we ever want to support futexes in memory shared between processes,
    // we'll need to change this.  The most foolproof way to do so is probably
    // to change PluginPhysicalPtr to be a bigger struct that identifies where
    // the mapped region came from (e.g. what file), and the offset into that
    // region. Such "fat" physical pointers might make memory management a
    // little more cumbersome though, e.g. when using them as keys in the futex
    // table.
    //
    // Alternatively we could hash the region+offset to a 64-bit value, but
    // then we'd need to deal with potential collisions. On average we'd expect
    // a collision after 2**32 physical addresses; i.e. they *probably*
    // wouldn't happen in practice for realistic simulations.

    // Linux uses the bottom 48-bits for user-space virtual addresses, giving
    // us 16 bits for the pid.
    const int pid_bits = 16;

    guint pid = process_getProcessID(proc);
    const int pid_shift = 64 - pid_bits;
    uint64_t high = (uint64_t)pid << pid_shift;
    utility_debugAssert(high >> pid_shift == pid);

    uint64_t low = vPtr.val;
    utility_debugAssert(low >> pid_shift == 0);

    return (PluginPhysicalPtr){.val = low | high};
}

int process_readPtr(Process* proc, void* dst, PluginVirtualPtr src, size_t n) {
    MAGIC_ASSERT(proc);

    // Disallow additional references while there's a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);

    return _process_readPtr(proc->rustProcess, dst, src, n);
}

int process_writePtr(Process* proc, PluginVirtualPtr dst, const void* src, size_t n) {
    MAGIC_ASSERT(proc);

    // Disallow additional references when trying to get a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);
    utility_debugAssert(proc->memoryRefs->len == 0);

    return _process_writePtr(proc->rustProcess, dst, src, n);
}

const void* process_getReadablePtr(Process* proc, PluginPtr plugin_src, size_t n) {
    MAGIC_ASSERT(proc);

    // Disallow additional references while there's a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);

    ProcessMemoryRef_u8* ref = _process_getReadablePtr(proc->rustProcess, plugin_src, n);
    if (!ref) {
        return NULL;
    }

    g_array_append_val(proc->memoryRefs, ref);
    return memorymanagerref_ptr(ref);
}

int process_getReadableString(Process* proc, PluginPtr plugin_src, size_t n, const char** out_str,
                              size_t* out_strlen) {
    MAGIC_ASSERT(proc);

    // Disallow additional references while there's a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);

    ProcessMemoryRef_u8* ref = _process_getReadablePtrPrefix(proc->rustProcess, plugin_src, n);
    if (!ref) {
        return -EFAULT;
    }

    size_t nbytes = memorymanagerref_sizeof(ref);
    const char* str = memorymanagerref_ptr(ref);
    size_t strlen = strnlen(str, nbytes);
    if (strlen == nbytes) {
        // No NULL byte.
        memorymanager_freeRef(ref);
        return -ENAMETOOLONG;
    }

    utility_debugAssert(out_str);
    *out_str = str;
    if (out_strlen) {
        *out_strlen = strlen;
    }

    g_array_append_val(proc->memoryRefs, ref);

    return 0;
}

ssize_t process_readString(Process* proc, char* str, PluginVirtualPtr src, size_t n) {
    MAGIC_ASSERT(proc);

    // Disallow additional references while there's a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);

    return _process_readString(proc->rustProcess, src, str, n);
}

// Returns a writable pointer corresponding to the named region. The initial
// contents of the returned memory are unspecified.
//
// The returned pointer is automatically invalidated when the plugin runs again.
void* process_getWriteablePtr(Process* proc, PluginPtr plugin_src, size_t n) {
    MAGIC_ASSERT(proc);

    // Disallow additional references when trying to get a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);
    utility_debugAssert(proc->memoryRefs->len == 0);

    ProcessMemoryRefMut_u8* ref = process_getWritablePtrRef(proc, plugin_src, n);
    if (!ref) {
        return NULL;
    }

    proc->memoryMutRef = ref;
    return memorymanagermut_ptr(ref);
}

// Returns a writeable pointer corresponding to the specified src. Use when
// the data at the given address needs to be both read and written.
//
// The returned pointer is automatically invalidated when the plugin runs again.
void* process_getMutablePtr(Process* proc, PluginPtr plugin_src, size_t n) {
    MAGIC_ASSERT(proc);

    // Disallow additional references when trying to get a mutable reference.
    utility_debugAssert(!proc->memoryMutRef);
    utility_debugAssert(proc->memoryRefs->len == 0);

    ProcessMemoryRefMut_u8* ref = _process_getMutablePtr(proc->rustProcess, plugin_src, n);
    if (!ref) {
        return NULL;
    }

    proc->memoryMutRef = ref;
    return memorymanagermut_ptr(ref);
}

static void _process_freeReaders(Process* proc) {
    // Free any readers
    if (proc->memoryRefs->len > 0) {
        for (int i = 0; i < proc->memoryRefs->len; ++i) {
            ProcessMemoryRef_u8* ref = g_array_index(proc->memoryRefs, ProcessMemoryRef_u8*, i);
            memorymanager_freeRef(ref);
        }
        proc->memoryRefs = g_array_set_size(proc->memoryRefs, 0);
    }
}

// Flushes and invalidates all previously returned readable/writeable plugin
// pointers, as if returning control to the plugin. This can be useful in
// conjunction with `thread_nativeSyscall` operations that touch memory.
void process_flushPtrs(Process* proc) {
    MAGIC_ASSERT(proc);

    _process_freeReaders(proc);

    // Flush and free any writers
    if (proc->memoryMutRef) {
        int rv = memorymanager_freeMutRefWithFlush(proc->memoryMutRef);
        if (rv) {
            panic("Couldn't flush mutable reference");
        }
        proc->memoryMutRef = NULL;
    }
}

void process_freePtrsWithoutFlushing(Process* proc) {
    MAGIC_ASSERT(proc);

    _process_freeReaders(proc);

    // Flush and free any writers
    if (proc->memoryMutRef) {
        trace("Discarding plugin ptr without writing back.");
        memorymanager_freeMutRefWithoutFlush(proc->memoryMutRef);
        proc->memoryMutRef = NULL;
    }
}

// ******************************************************
// Handle the descriptors owned by this process
// ******************************************************

bool process_parseArgStr(const char* commandLine, int* argc, char*** argv, char** error) {
    GError* gError = NULL;

    bool rv = !!g_shell_parse_argv(commandLine, argc, argv, &gError);
    if (!rv && gError != NULL && gError->message != NULL && error != NULL) {
        *error = strdup(gError->message);
    }

    if (gError != NULL) {
        g_error_free(gError);
    }
    return rv;
}

void process_parseArgStrFree(char** argv, char* error) {
    if (argv != NULL) {
        g_strfreev(argv);
    }
    if (error != NULL) {
        g_free(error);
    }
}

static void _process_interruptWithSignal(Process* process, ShimShmemHostLock* hostLock, int signo) {
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, process->threads);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        Thread* thread = value;

        // Find a thread without the signal blocked, if any, and wake it up.
        shd_kernel_sigset_t blocked_signals =
            shimshmem_getBlockedSignals(hostLock, thread_sharedMem(thread));
        if (!shd_sigismember(&blocked_signals, signo)) {
            SysCallCondition* cond = thread_getSysCallCondition(thread);
            if (!cond) {
                continue;
            }
            syscallcondition_wakeupForSignal(cond, hostLock, signo);
            break;
        }
    }
}

void process_signal(Process* process, Thread* currentRunningThread, const siginfo_t* siginfo) {
    MAGIC_ASSERT(process);
    utility_debugAssert(siginfo->si_signo >= 0);
    utility_debugAssert(siginfo->si_signo <= SHD_SIGRT_MAX);
    utility_debugAssert(siginfo->si_signo <= SHD_STANDARD_SIGNAL_MAX_NO);

    if (siginfo->si_signo == 0) {
        return;
    }

    const Host* host = _host(process);

    struct shd_kernel_sigaction action = shimshmem_getSignalAction(
        host_getShimShmemLock(host), process_getSharedMem(process), siginfo->si_signo);
    if (action.u.ksa_handler == SIG_IGN ||
        (action.u.ksa_handler == SIG_DFL &&
         shd_defaultAction(siginfo->si_signo) == SHD_KERNEL_DEFAULT_ACTION_IGN)) {
        // Don't deliver an ignored signal.
        return;
    }

    shd_kernel_sigset_t pending_signals = shimshmem_getProcessPendingSignals(
        host_getShimShmemLock(host), process_getSharedMem(process));

    if (shd_sigismember(&pending_signals, siginfo->si_signo)) {
        // Signal is already pending. From signal(7):In the case where a standard signal is already
        // pending, the siginfo_t structure (see sigaction(2)) associated with  that  signal is not
        // overwritten on arrival of subsequent instances of the same signal.
        return;
    }

    shd_sigaddset(&pending_signals, siginfo->si_signo);
    shimshmem_setProcessPendingSignals(
        host_getShimShmemLock(host), process_getSharedMem(process), pending_signals);
    shimshmem_setProcessSiginfo(
        host_getShimShmemLock(host), process_getSharedMem(process), siginfo->si_signo, siginfo);

    if (currentRunningThread != NULL && thread_getProcess(currentRunningThread) == process) {
        shd_kernel_sigset_t blocked_signals = shimshmem_getBlockedSignals(
            host_getShimShmemLock(host), thread_sharedMem(currentRunningThread));
        if (!shd_sigismember(&blocked_signals, siginfo->si_signo)) {
            // Target process is this process, and current thread hasn't blocked
            // the signal.  It will be delivered to this thread when it resumes.
            return;
        }
    }

    _process_interruptWithSignal(process, host_getShimShmemLock(host), siginfo->si_signo);
}

int process_getDumpable(Process* process) {
    return _process_getDumpable(process->rustProcess);
}

void process_setDumpable(Process* process, int dumpable) {
    _process_setDumpable(process->rustProcess, dumpable);
}
