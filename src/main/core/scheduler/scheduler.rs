use std::cell::RefCell;
use std::marker::PhantomData;
use std::sync::Mutex;

use crate::core::scheduler::workpool::{TaskRunner, WorkerPool};
use crate::host::host::Host;

std::thread_local! {
    pub static THREAD_HOST: RefCell<Option<Host>> = RefCell::new(None);
}

pub struct NewScheduler {
    pool: WorkerPool,
}

impl NewScheduler {
    pub fn new<T>(num_threads: u32, hosts: T, use_pinning: bool) -> Self
    where
        T: IntoIterator<Item = Host>,
        <T as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let hosts = hosts.into_iter();

        let mut pool = WorkerPool::new(num_threads, hosts.len() as u32, use_pinning);

        let hosts: Vec<Mutex<Option<Host>>> = hosts.map(|x| Mutex::new(Some(x))).collect();

        pool.scope(|s| {
            s.run(|index, _, _| {
                let index = index as usize;
                THREAD_HOST
                    .with(|x| *x.borrow_mut() = Some(hosts[index].lock().unwrap().take().unwrap()));
            });
        });

        Self {
            pool,
        }
    }

    /// The maximum number of threads that will ever be run in parallel.
    pub fn parallelism(&self) -> usize {
        self.pool.parallelism()
    }

    /// A scope for any task run on the scheduler. The current thread will block at the end of the
    /// scope until the task has completed.
    pub fn scope<'scope>(
        &'scope mut self,
        f: impl for<'a, 'b> FnOnce(SchedScope<'a, 'b, 'scope>) + 'scope,
    ) {
        // we cannot access `self` after calling `pool.scope()` since `SchedScope` has a lifetime of
        // `'scope` (which at minimum spans the entire function)

        self.pool.scope(move |s| {
            let sched_scope = SchedScope {
                runner: s,
                marker: Default::default(),
            };

            (f)(sched_scope);
        });
    }

    /// Join all threads started by the scheduler.
    pub fn join(mut self) {
        let hosts: Vec<Mutex<Option<Host>>> = (0..self.pool.num_threads())
            .map(|_| Mutex::new(None))
            .collect();

        self.pool.scope(|s| {
            s.run(|index, _, _| {
                let index = index as usize;
                THREAD_HOST.with(|x| {
                    *hosts[index].lock().unwrap() = x.borrow_mut().take();
                });
            });
        });

        // need to unref the host from the main thread so that the allocation counter will be
        // correctly updated
        for host in hosts {
            if let Some(host) = host.lock().unwrap().take() {
                use crate::cshadow as c;
                unsafe { c::host_unref(host.chost()) };
            }
        }

        self.pool.join();
    }
}

pub struct SchedScope<'sched, 'pool, 'scope>
where
    'sched: 'scope,
{
    runner: TaskRunner<'pool, 'scope>,
    marker: PhantomData<&'sched Host>,
}

impl<'sched, 'pool, 'scope> SchedScope<'sched, 'pool, 'scope> {
    /// Run the closure on all threads.
    pub fn run(self, f: impl Fn(usize) + Sync + Send + 'scope) {
        self.runner.run(move |i, _, cpu_id| {
            crate::core::worker::Worker::set_affinity(cpu_id);
            (f)(i as usize)
        });
    }

    /// Run the closure on all threads.
    ///
    /// You must iterate over the provided `HostIter` to completion (until `next()` returns `None`),
    /// otherwise this will panic.
    pub fn run_with_hosts(self, f: impl Fn(usize, &mut HostIter) + Send + Sync + 'scope) {
        self.runner.run(move |i, _, cpu_id| {
            crate::core::worker::Worker::set_affinity(cpu_id);
            let i = i as usize;

            THREAD_HOST.with(|x| {
                let mut host = x.borrow_mut();

                let mut host_iter = HostIter {
                    host: Some(host.as_mut().unwrap()),
                };

                f(i, &mut host_iter);
            });
        });
    }

    /// Run the closure on all threads. The element given to the closure will not be given to any
    /// other thread while this closure is running, which means you should not expect any contention
    /// on this element if using interior mutability.
    ///
    /// You must iterate over the provided `HostIter` to completion (until `next()` returns `None`),
    /// otherwise this will panic.
    ///
    /// The provided slice must have a length of at least `NewScheduler::parallelism`. If the data
    /// needs to be initialized, it should be initialized before calling this function and not at
    /// the beginning of the closure.
    pub fn run_with_data<T>(
        self,
        elems: &'scope [T],
        f: impl Fn(usize, &mut HostIter, &T) + Send + Sync + 'scope,
    ) where
        T: Sync,
    {
        self.runner.run(move |i, j, cpu_id| {
            crate::core::worker::Worker::set_affinity(cpu_id);
            let i = i as usize;
            let j = j as usize;
            let this_elem = &elems[j];

            THREAD_HOST.with(|x| {
                let mut host = x.borrow_mut();

                let mut host_iter = HostIter {
                    host: Some(host.as_mut().unwrap()),
                };

                f(i, &mut host_iter, this_elem);
            });
        });
    }
}

pub struct HostIter<'a> {
    host: Option<&'a mut Host>,
}

impl<'a> HostIter<'a> {
    /// Get the next host.
    pub fn next(&mut self) -> Option<&mut Host> {
        self.host.take()
    }
}
