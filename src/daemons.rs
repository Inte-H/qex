//! This module measures the work that a job gives to a process outside its
//! process group, through a TCP connection on this machine.
//!
//! A build tool such as Gradle keeps a daemon that lives longer than one
//! build. The daemon makes a process group of its own, so the measurement of
//! the job group does not see it, and a job that gives all of its work to the
//! daemon reads as a job that uses nothing. The learned claim then becomes the
//! smallest claim, and the reclaim of idle cores takes the cores of a job that
//! is busy.
//!
//! The method only reads `/proc`. It makes no cgroup and moves no process.
//!
//! The limits:
//! - Linux only. Another system gives no value, and the job keeps the
//!   measurement of its own group.
//! - TCP only. A Unix socket often goes to a daemon that many programs share,
//!   such as the session bus, and its use is not the use of the job.
//! - A process of another user is not counted.
//! - A daemon that works for two jobs at the same time counts its whole work
//!   for each of them. The claim then becomes larger, which is the safe side.

use std::collections::BTreeMap;

/// The use of one job: its process group, and the processes that it is
/// connected to.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct JobUse {
    /// The number of processes in the job group.
    pub processes: usize,
    /// The CPU time of the job group, with the children that it reaped, and
    /// the CPU time that the connected processes used while this measurement
    /// saw the connection.
    pub cpu_secs: f64,
    /// The memory of the job group and of the connected processes, now.
    pub rss: u64,
    /// The number of connected processes, with their descendants.
    pub linked: usize,
}

/// One connected process and its descendants.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Linked {
    pub pid: i32,
    pub start: Option<u64>,
    pub cpu_secs: f64,
    pub rss: u64,
    pub processes: usize,
}

/// The CPU time that the connected processes used, from the first measurement
/// that saw each connection.
///
/// A daemon already holds the CPU time of the earlier builds, so the first
/// measurement of a connection gives only the start point. A connection that
/// the last measurement did not see starts again, so the time between two
/// connections is not counted.
#[derive(Debug, Default)]
pub struct DaemonUse {
    last: BTreeMap<(i32, Option<u64>), f64>,
    cpu_secs: f64,
}

impl DaemonUse {
    /// The CPU time that the connected processes used, in seconds.
    pub fn cpu_secs(&self) -> f64 {
        self.cpu_secs
    }

    /// Measures the job group `pgid` and the processes that it is connected
    /// to.
    #[cfg(target_os = "linux")]
    pub fn measure(&mut self, pgid: i32) -> JobUse {
        let table = crate::sys::processes();
        let uid = unsafe { libc::getuid() };
        let links = crate::sys::tcp_links();
        let linked = find_linked(pgid, uid, &table, &links, crate::sys::socket_inodes);
        self.observe(&linked);

        let group = table.iter().filter(|p| p.pgid == pgid);
        JobUse {
            processes: group.clone().count(),
            cpu_secs: group.clone().map(|p| p.cpu_secs).sum::<f64>() + self.cpu_secs,
            rss: group.map(|p| p.rss).sum::<u64>() + linked.iter().map(|l| l.rss).sum::<u64>(),
            linked: linked.iter().map(|l| l.processes).sum(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn measure(&mut self, pgid: i32) -> JobUse {
        let usage = crate::sys::group_usage(pgid);
        JobUse {
            processes: usage.processes,
            cpu_secs: usage.cpu_secs + usage.reaped_cpu_secs,
            rss: usage.rss,
            linked: 0,
        }
    }

    pub fn observe(&mut self, linked: &[Linked]) {
        let mut next = BTreeMap::new();
        for process in linked {
            let key = (process.pid, process.start);
            // A total that falls says that a descendant stopped and a process
            // outside the tree reaped it. That is no use, so it is a new start.
            if let Some(&before) = self.last.get(&key) {
                if process.cpu_secs >= before {
                    self.cpu_secs += process.cpu_secs - before;
                }
            }
            next.insert(key, process.cpu_secs);
        }
        self.last = next;
    }
}

/// Finds the processes of user `uid`, outside the group `pgid`, that hold the
/// other end of a TCP connection of the group, and measures each of them with
/// its descendants.
///
/// A process that is a descendant of another connected process is counted once,
/// inside the tree of that process. A process of the job group is never
/// counted, because the measurement of the group holds it.
#[cfg(target_os = "linux")]
pub fn find_linked(
    pgid: i32,
    uid: u32,
    table: &[crate::sys::ProcessUse],
    links: &[crate::sys::TcpLink],
    sockets: impl Fn(i32) -> Vec<u64>,
) -> Vec<Linked> {
    use std::collections::{BTreeSet, HashMap};

    let by_inode: HashMap<u64, &crate::sys::TcpLink> = links.iter().map(|l| (l.inode, l)).collect();
    let by_ends: HashMap<_, u64> = links
        .iter()
        .map(|l| ((l.local, l.remote), l.inode))
        .collect();

    let mut wanted: BTreeSet<u64> = BTreeSet::new();
    for process in table.iter().filter(|p| p.pgid == pgid) {
        for inode in sockets(process.pid) {
            if let Some(link) = by_inode.get(&inode) {
                if let Some(&other) = by_ends.get(&(link.remote, link.local)) {
                    wanted.insert(other);
                }
            }
        }
    }
    if wanted.is_empty() {
        return Vec::new();
    }

    let mut owners: BTreeSet<i32> = BTreeSet::new();
    for process in table.iter().filter(|p| p.uid == uid && p.pgid != pgid) {
        if wanted.is_empty() {
            break;
        }
        let held: Vec<u64> = sockets(process.pid)
            .into_iter()
            .filter(|inode| wanted.contains(inode))
            .collect();
        if !held.is_empty() {
            owners.insert(process.pid);
            for inode in held {
                wanted.remove(&inode);
            }
        }
    }

    let by_pid: HashMap<i32, &crate::sys::ProcessUse> = table.iter().map(|p| (p.pid, p)).collect();
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for process in table {
        children.entry(process.ppid).or_default().push(process.pid);
    }
    let below_another = |pid: i32| {
        let mut at = by_pid.get(&pid).map(|p| p.ppid);
        let mut steps = 0;
        while let Some(parent) = at {
            if owners.contains(&parent) {
                return true;
            }
            steps += 1;
            if parent <= 1 || steps > table.len() {
                return false;
            }
            at = by_pid.get(&parent).map(|p| p.ppid);
        }
        false
    };

    owners
        .iter()
        .filter(|pid| !below_another(**pid))
        .filter_map(|pid| {
            let root = by_pid.get(pid)?;
            let mut out = Linked {
                pid: root.pid,
                start: root.start,
                cpu_secs: 0.0,
                rss: 0,
                processes: 0,
            };
            let mut todo = vec![root.pid];
            while let Some(at) = todo.pop() {
                let Some(process) = by_pid.get(&at) else {
                    continue;
                };
                if process.pgid == pgid {
                    continue;
                }
                out.cpu_secs += process.cpu_secs;
                out.rss += process.rss;
                out.processes += 1;
                todo.extend(children.get(&at).into_iter().flatten().copied());
            }
            Some(out)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linked(pid: i32, cpu_secs: f64) -> Linked {
        Linked {
            pid,
            start: Some(100),
            cpu_secs,
            rss: 1 << 20,
            processes: 1,
        }
    }

    #[test]
    fn the_first_measurement_of_a_connection_counts_no_time() {
        let mut use_ = DaemonUse::default();
        use_.observe(&[linked(10, 500.0)]);
        assert_eq!(
            use_.cpu_secs(),
            0.0,
            "the daemon brought 500s from earlier builds"
        );
        use_.observe(&[linked(10, 503.5)]);
        assert_eq!(use_.cpu_secs(), 3.5);
    }

    #[test]
    fn the_time_between_two_connections_is_not_counted() {
        let mut use_ = DaemonUse::default();
        use_.observe(&[linked(10, 500.0)]);
        use_.observe(&[linked(10, 502.0)]);
        use_.observe(&[]);
        use_.observe(&[linked(10, 900.0)]);
        use_.observe(&[linked(10, 901.0)]);
        assert_eq!(use_.cpu_secs(), 3.0);
    }

    #[test]
    fn a_total_that_falls_starts_again() {
        let mut use_ = DaemonUse::default();
        use_.observe(&[linked(10, 500.0)]);
        use_.observe(&[linked(10, 400.0)]);
        use_.observe(&[linked(10, 401.0)]);
        assert_eq!(use_.cpu_secs(), 1.0);
    }

    #[test]
    fn a_new_process_with_the_same_pid_starts_again() {
        let mut use_ = DaemonUse::default();
        use_.observe(&[linked(10, 5.0)]);
        let mut other = linked(10, 50.0);
        other.start = Some(200);
        use_.observe(&[other]);
        assert_eq!(use_.cpu_secs(), 0.0);
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::super::*;
        use crate::sys::{ProcessUse, TcpLink};

        fn process(pid: i32, ppid: i32, pgid: i32, uid: u32, cpu_secs: f64) -> ProcessUse {
            ProcessUse {
                pid,
                ppid,
                pgid,
                uid,
                start: Some(1),
                cpu_secs,
                rss: 1000,
            }
        }

        fn link(local: u16, remote: u16, inode: u64) -> TcpLink {
            TcpLink {
                local: ([127, 0, 0, 1], local).into(),
                remote: ([127, 0, 0, 1], remote).into(),
                inode,
            }
        }

        /// The job group 50 holds socket 1. Its other end, socket 2, belongs to
        /// the process `owner`.
        fn one_connection(owner: i32) -> (Vec<TcpLink>, impl Fn(i32) -> Vec<u64>) {
            let links = vec![link(40000, 5000, 1), link(5000, 40000, 2)];
            let sockets = move |pid: i32| match pid {
                50 => vec![1],
                p if p == owner => vec![2],
                _ => vec![],
            };
            (links, sockets)
        }

        #[test]
        fn the_daemon_and_its_descendants_are_counted() {
            let table = vec![
                process(50, 1, 50, 7, 1.0),
                process(60, 1, 60, 7, 100.0),
                process(61, 60, 60, 7, 30.0),
                process(62, 61, 62, 7, 4.0),
            ];
            let (links, sockets) = one_connection(60);
            let found = find_linked(50, 7, &table, &links, sockets);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].pid, 60);
            assert_eq!(found[0].cpu_secs, 134.0);
            assert_eq!(found[0].processes, 3);
            assert_eq!(found[0].rss, 3000);
        }

        #[test]
        fn a_process_of_another_user_is_not_counted() {
            let table = vec![process(50, 1, 50, 7, 1.0), process(60, 1, 60, 8, 100.0)];
            let (links, sockets) = one_connection(60);
            assert!(find_linked(50, 7, &table, &links, sockets).is_empty());
        }

        #[test]
        fn a_job_without_a_connection_has_no_daemon() {
            let table = vec![process(50, 1, 50, 7, 1.0), process(60, 1, 60, 7, 100.0)];
            let links = vec![link(5000, 40000, 2)];
            let sockets = |pid: i32| if pid == 60 { vec![2] } else { vec![] };
            assert!(find_linked(50, 7, &table, &links, sockets).is_empty());
        }

        #[test]
        fn a_connection_inside_the_job_group_is_not_a_daemon() {
            let table = vec![process(50, 1, 50, 7, 1.0), process(51, 50, 50, 7, 9.0)];
            let (links, sockets) = one_connection(51);
            assert!(find_linked(50, 7, &table, &links, sockets).is_empty());
        }

        #[test]
        fn a_connected_descendant_of_a_connected_daemon_is_counted_once() {
            let table = vec![
                process(50, 1, 50, 7, 1.0),
                process(60, 1, 60, 7, 100.0),
                process(61, 60, 60, 7, 30.0),
            ];
            let links = vec![
                link(40000, 5000, 1),
                link(5000, 40000, 2),
                link(40001, 5001, 3),
                link(5001, 40001, 4),
            ];
            let sockets = |pid: i32| match pid {
                50 => vec![1, 3],
                60 => vec![2],
                61 => vec![4],
                _ => vec![],
            };
            let found = find_linked(50, 7, &table, &links, sockets);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].cpu_secs, 130.0);
        }

        /// A real connection: a busy shell in a group of its own connects to a
        /// socket that a job group holds.
        #[test]
        fn a_busy_daemon_on_a_real_connection_counts_for_the_job() {
            use std::os::unix::process::CommandExt;
            use std::process::{Command, Stdio};

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let mut daemon = Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "exec 3<>/dev/tcp/127.0.0.1/{port}; while :; do :; done"
                ))
                .process_group(0)
                .spawn()
                .unwrap();
            let (stream, _) = listener.accept().unwrap();
            let mut job = Command::new("sleep")
                .arg("30")
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(stream)))
                .process_group(0)
                .spawn()
                .unwrap();
            let pgid = job.id() as i32;

            let mut meter = DaemonUse::default();
            let first = meter.measure(pgid);
            std::thread::sleep(std::time::Duration::from_millis(1500));
            let second = meter.measure(pgid);

            let _ = daemon.kill();
            let _ = job.kill();
            let _ = daemon.wait();
            let _ = job.wait();

            assert_eq!(first.processes, 1);
            assert_eq!(first.linked, 1, "the shell holds the other end");
            assert!(
                meter.cpu_secs() > 0.5,
                "the busy shell used {}s in 1.5s",
                meter.cpu_secs()
            );
            assert!(second.cpu_secs >= meter.cpu_secs());
            assert!(second.rss > first.rss / 2);
        }
    }
}
