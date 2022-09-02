use crate::core::scheduler::workpool::{TaskRunner, WorkerPool};
use crate::host::host::Host;

use crossbeam::queue::ArrayQueue;
//use crossbeam::utils::CachePadded;

pub struct NewScheduler {
    pool: WorkerPool,
    num_threads: usize,
    thread_hosts: Vec<ArrayQueue<Host>>,
    thread_hosts_processed: Vec<ArrayQueue<Host>>,
    hosts_need_swap: bool,
}

impl NewScheduler {
    pub fn new<T>(num_threads: u32, hosts: T) -> Self
    where
        T: IntoIterator<Item = Host>,
        <T as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let hosts = hosts.into_iter();

        let pool = WorkerPool::new(num_threads);

        // each thread gets two fixed-sized queues with enough capacity to store every host
        let thread_hosts: Vec<_> = (0..num_threads)
            .map(|_| ArrayQueue::new(hosts.len()))
            .collect();
        let thread_hosts_2: Vec<_> = (0..num_threads)
            .map(|_| ArrayQueue::new(hosts.len()))
            .collect();

        // assign hosts to threads in a round-robin manner
        for (thread_queue, host) in thread_hosts.iter().cycle().zip(hosts) {
            thread_queue.push(host).unwrap();
        }

        Self {
            pool,
            num_threads: num_threads as usize,
            thread_hosts,
            thread_hosts_processed: thread_hosts_2,
            hosts_need_swap: false,
        }
    }

    /// The maximum number of threads that will ever be run in parallel.
    pub fn parallelism(&self) -> usize {
        self.num_threads
    }

    /// A scope for any task run on the scheduler. The current thread will block at the end of the
    /// scope until the task has completed.
    pub fn scope<'scope>(
        &'scope mut self,
        f: impl for<'a, 'b> FnOnce(SchedScope<'a, 'b, 'scope>) + 'scope,
    ) {
        // we can't swap after the below `pool.scope()` due to lifetime restrictions, so we need to
        // do it before instead
        if self.hosts_need_swap {
            #[cfg(debug_assertions)]
            for queue in self.thread_hosts {
                assert_eq!(queue.len(), 0);
            }

            std::mem::swap(&mut self.thread_hosts, &mut self.thread_hosts_processed);
            self.hosts_need_swap = false;
        }

        // data/references that we'll pass to the scope
        let thread_hosts = &self.thread_hosts;
        let thread_hosts_processed = &self.thread_hosts_processed;
        let hosts_need_swap = &mut self.hosts_need_swap;

        // we cannot access `self` after calling `pool.scope()` since `SchedScope` has a lifetime of
        // `'scope` (which at minimum spans the entire function)

        self.pool.scope(move |s| {
            let sched_scope = SchedScope {
                thread_hosts,
                thread_hosts_processed,
                hosts_need_swap,
                runner: s,
            };

            (f)(sched_scope);
        });
    }

    /// Join all threads started by the scheduler.
    pub fn join(self) {
        self.pool.join();

        // when the host is in rust we won't need to do this
        for host_queue in self.thread_hosts.iter() {
            while let Some(host) = host_queue.pop() {
                use crate::cshadow as c;
                unsafe { c::host_unref(host.chost()) };
            }
        }
    }
}

pub struct SchedScope<'sched, 'pool, 'scope>
where
    'sched: 'scope,
{
    thread_hosts: &'sched Vec<ArrayQueue<Host>>,
    thread_hosts_processed: &'sched Vec<ArrayQueue<Host>>,
    hosts_need_swap: &'sched mut bool,
    runner: TaskRunner<'pool, 'scope>,
}

impl<'sched, 'pool, 'scope> SchedScope<'sched, 'pool, 'scope> {
    /// Run the closure on all threads.
    pub fn run(self, f: impl Fn(usize) + Sync + Send + 'scope) {
        self.runner.run(move |i| (f)(i as usize));
    }

    /// Run the closure on all threads.
    ///
    /// You must iterate over the provided `HostIter` to completion (until `next()` returns `None`),
    /// otherwise this will panic.
    pub fn run_with_hosts(self, f: impl Fn(usize, &mut HostIter) + Send + Sync + 'scope) {
        self.runner.run(move |i| {
            let i = i as usize;

            let mut host_iter = HostIter {
                thread_hosts_from: &self.thread_hosts,
                thread_hosts_to: &self.thread_hosts_processed[i],
                this_thread_index: i,
                thread_index_iter_offset: 0,
                current_host: None,
            };

            f(i, &mut host_iter);

            assert!(host_iter.current_host.is_none());
            assert!(host_iter.next().is_none());
        });

        *self.hosts_need_swap = true;
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
        self.runner.run(move |i| {
            let i = i as usize;
            let this_elem = &elems[i];

            let mut host_iter = HostIter {
                thread_hosts_from: &self.thread_hosts[..],
                thread_hosts_to: &self.thread_hosts_processed[i],
                this_thread_index: i,
                thread_index_iter_offset: 0,
                current_host: None,
            };

            f(i, &mut host_iter, this_elem);

            assert!(host_iter.current_host.is_none());
            assert!(host_iter.next().is_none());
        });

        *self.hosts_need_swap = true;
    }
}

pub struct HostIter<'a> {
    /// Queues to take hosts from.
    thread_hosts_from: &'a [ArrayQueue<Host>],
    /// The queue to add hosts to when done with them.
    thread_hosts_to: &'a ArrayQueue<Host>,
    /// The index of this thread. This is the first queue of `thread_hosts_from` that we take hosts
    /// from.
    this_thread_index: usize,
    /// The thread offset of our iterator; stored so that we can resume where we left off.
    thread_index_iter_offset: usize,
    /// The host that was last returned from `next()`.
    current_host: Option<Host>,
}

impl<'a> HostIter<'a> {
    /// Get the next host.
    pub fn next(&mut self) -> Option<&mut Host> {
        // a generator would be nice here...
        let num_threads = self.thread_hosts_from.len();

        self.return_current_host();

        while self.thread_index_iter_offset < num_threads {
            let iter_thread_index = self.this_thread_index + self.thread_index_iter_offset;
            let queue = &self.thread_hosts_from[iter_thread_index % num_threads];

            match queue.pop() {
                Some(host) => {
                    // yield the host, but keep ownership so that we can add it back to the proper
                    // queue later
                    self.current_host = Some(host);
                    return self.current_host.as_mut();
                }
                // no hosts remaining, so move on to the next queue
                None => self.thread_index_iter_offset += 1,
            }
        }

        None
    }

    /// Returns the currently stored host back to a queue.
    fn return_current_host(&mut self) {
        if let Some(current_host) = self.current_host.take() {
            self.thread_hosts_to.push(current_host).unwrap();
        }
    }
}

impl<'a> std::ops::Drop for HostIter<'a> {
    fn drop(&mut self) {
        // make sure we don't own and drop a host
        self.return_current_host();
    }
}
