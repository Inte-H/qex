//! This module counts a job that uses little of its cores, for a long time, as
//! a job that holds only the cores that it uses.
//!
//! The rule changes only the test of the budget before a job starts. The
//! record of the job, the devices that qex gives, the claims that the other
//! users read and `qex info` keep the claim that the job gave.
//!
//! The memory is never reclaimed. A job can return to its peak of memory at
//! any moment, and a job that took that memory would then be killed. A core
//! that two jobs share only makes both of them slower.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The scheduler turns every 500ms. A measurement reads every process of the
/// machine, and a use over 500ms is mostly noise.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
struct Sample {
    pid: i32,
    cpu_secs: f64,
    at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Track {
    last: Sample,
    /// The start of the measurements that were all below the limit, without
    /// a gap. `None` when the last measurement was above it.
    low_since: Option<Instant>,
    /// The largest use, in cores, since `low_since`.
    peak: f64,
}

#[derive(Debug, Default)]
pub struct Relax {
    tracks: BTreeMap<uuid::Uuid, Track>,
    sampled_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
pub struct Observed {
    pub id: uuid::Uuid,
    pub claim: u64,
    pub pid: i32,
    pub cpu_secs: f64,
}

impl Relax {
    pub fn due(&self, now: Instant) -> bool {
        self.sampled_at
            .map(|t| now.duration_since(t) >= SAMPLE_EVERY)
            .unwrap_or(true)
    }

    /// A job that is not in `jobs` stopped, so its track goes away. `below` is
    /// the limit as a percentage of the claim.
    pub fn observe(&mut self, now: Instant, below: f64, jobs: &[Observed]) {
        let mut next = BTreeMap::new();
        for job in jobs {
            let sample = Sample {
                pid: job.pid,
                cpu_secs: job.cpu_secs,
                at: now,
            };
            // A new attempt has a new process and a CPU time that starts at
            // 0, so its first measurement is a new start.
            let fresh = Track {
                last: sample,
                low_since: None,
                peak: 0.0,
            };
            let track = match self.tracks.get(&job.id) {
                Some(old) if old.last.pid == job.pid => {
                    // A measurement that the scheduler missed averages the use
                    // over a longer time than it watched, and a total that
                    // falls says that the measurement did not see every
                    // process. Neither lifts a claim, so the time starts again.
                    let gap = now.duration_since(old.last.at);
                    match use_in_cores(&old.last, &sample) {
                        Some(cores)
                            if gap <= SAMPLE_EVERY * 2 && is_low(cores, job.claim, below) =>
                        {
                            Track {
                                last: sample,
                                low_since: Some(old.low_since.unwrap_or(old.last.at)),
                                peak: if old.low_since.is_some() {
                                    old.peak.max(cores)
                                } else {
                                    cores
                                },
                            }
                        }
                        _ => fresh,
                    }
                }
                _ => fresh,
            };
            next.insert(job.id, track);
        }
        self.tracks = next;
        self.sampled_at = Some(now);
    }

    pub fn counted(
        &self,
        id: &uuid::Uuid,
        claim: u64,
        pid: Option<i32>,
        after: Duration,
        now: Instant,
    ) -> u64 {
        match (self.tracks.get(id), pid) {
            (
                Some(Track {
                    last,
                    low_since: Some(since),
                    peak,
                }),
                Some(pid),
            ) if last.pid == pid && now.duration_since(*since) >= after => {
                counted_cores(claim, *peak)
            }
            _ => claim,
        }
    }
}

/// A total that falls, or a time that does not move, gives no answer instead
/// of no use: a missing measurement must never read as an idle job.
fn use_in_cores(earlier: &Sample, later: &Sample) -> Option<f64> {
    let seconds = later.at.duration_since(earlier.at).as_secs_f64();
    if seconds <= 0.0 || later.cpu_secs < earlier.cpu_secs {
        return None;
    }
    Some((later.cpu_secs - earlier.cpu_secs) / seconds)
}

pub fn is_low(cores: f64, claim: u64, below: f64) -> bool {
    cores < claim as f64 * below / 100.0
}

pub fn counted_cores(claim: u64, peak: f64) -> u64 {
    let used = (peak.max(0.0).ceil() as u64).max(1);
    used.min(claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(pid: i32, claim: u64, cpu_secs: f64) -> Observed {
        Observed {
            id: uuid::Uuid::nil(),
            claim,
            pid,
            cpu_secs,
        }
    }

    /// Observes the job of the tests `steps` times, one `SAMPLE_EVERY` apart,
    /// with the CPU time that `cpu` gives for each step, and answers the cores
    /// that the job counts as at the last measurement.
    ///
    /// The answer asks for an answer of `after` from the same process.
    fn walk(
        relax: &mut Relax,
        claim: u64,
        below: f64,
        after: Duration,
        steps: usize,
        cpu: impl Fn(usize) -> f64,
    ) -> u64 {
        let t0 = Instant::now();
        let mut at = t0;
        for step in 0..=steps {
            relax.observe(at, below, &[job(100, claim, cpu(step))]);
            if step < steps {
                at += SAMPLE_EVERY;
            }
        }
        relax.counted(&uuid::Uuid::nil(), claim, Some(100), after, at)
    }

    #[test]
    fn counted_cores_rounds_up_and_never_gives_zero_or_more_than_the_claim() {
        assert_eq!(counted_cores(2, 0.0), 1);
        assert_eq!(counted_cores(4, 1.5), 2);
        assert_eq!(counted_cores(1, 0.0), 1);
        assert_eq!(counted_cores(2, 7.0), 2);
    }

    #[test]
    fn is_low_compares_with_the_part_of_the_claim() {
        assert!(is_low(0.4, 2, 25.0));
        assert!(!is_low(0.5, 2, 25.0));
        assert!(!is_low(0.0, 2, 0.0));
    }

    #[test]
    fn a_job_that_stays_low_for_the_whole_time_holds_one_core() {
        let mut relax = Relax::default();
        let after = SAMPLE_EVERY * 2;
        assert_eq!(walk(&mut relax, 2, 25.0, after, 1, |_| 0.0), 2);
        assert_eq!(walk(&mut relax, 2, 25.0, after, 2, |_| 0.0), 1);
    }

    #[test]
    fn one_busy_measurement_starts_the_time_again() {
        let mut relax = Relax::default();
        let after = SAMPLE_EVERY * 2;
        // Two cores for one measurement, which is not below 25% of 2.
        let busy = |step: usize| if step < 3 { 0.0 } else { 10.0 };
        assert_eq!(walk(&mut relax, 2, 25.0, after, 4, busy), 2);
        assert_eq!(walk(&mut relax, 2, 25.0, after, 6, busy), 1);
    }

    #[test]
    fn a_total_that_falls_or_a_measurement_that_was_missed_starts_the_time_again() {
        let id = uuid::Uuid::nil();
        let after = SAMPLE_EVERY * 2;
        let t0 = Instant::now();
        let mut relax = Relax::default();
        for step in 0..=2 {
            relax.observe(t0 + SAMPLE_EVERY * step, 25.0, &[job(100, 2, 10.0)]);
        }
        assert_eq!(
            relax.counted(&id, 2, Some(100), after, t0 + SAMPLE_EVERY * 2),
            1
        );

        // The CPU time of the group falls when a child stops before its parent
        // waits for it, so this measurement did not see every process.
        relax.observe(t0 + SAMPLE_EVERY * 3, 25.0, &[job(100, 2, 5.0)]);
        assert_eq!(
            relax.counted(&id, 2, Some(100), after, t0 + SAMPLE_EVERY * 3),
            2
        );

        for step in 4..=5 {
            relax.observe(t0 + SAMPLE_EVERY * step, 25.0, &[job(100, 2, 5.0)]);
        }
        assert_eq!(
            relax.counted(&id, 2, Some(100), after, t0 + SAMPLE_EVERY * 5),
            1
        );

        // The scheduler missed two measurements, and the use over the whole
        // gap says nothing about the time after it.
        relax.observe(t0 + SAMPLE_EVERY * 8, 25.0, &[job(100, 2, 5.0)]);
        assert_eq!(
            relax.counted(&id, 2, Some(100), after, t0 + SAMPLE_EVERY * 8),
            2
        );
    }

    #[test]
    fn a_new_attempt_and_a_stopped_job_lose_their_measurements() {
        let mut relax = Relax::default();
        let after = SAMPLE_EVERY * 2;
        assert_eq!(walk(&mut relax, 2, 25.0, after, 2, |_| 0.0), 1);

        let at = Instant::now();
        relax.observe(at, 25.0, &[job(200, 2, 0.0)]);
        assert_eq!(
            relax.counted(&uuid::Uuid::nil(), 2, Some(200), after, at),
            2
        );
        // The scheduler asks about the process it saw, not about the attempt
        // that the track still remembers.
        assert_eq!(
            relax.counted(&uuid::Uuid::nil(), 2, Some(100), after, at),
            2
        );

        relax.observe(at + SAMPLE_EVERY, 25.0, &[]);
        assert!(relax.tracks.is_empty());
    }

    #[test]
    fn the_largest_use_of_the_low_time_decides_the_count() {
        let mut relax = Relax::default();
        let after = SAMPLE_EVERY * 2;
        // 1.5 cores for every measurement, below 2 cores (25% of 8).
        let rising = |step: usize| 7.5 * step as f64;
        assert_eq!(walk(&mut relax, 8, 25.0, after, 2, rising), 2);
    }

    #[test]
    fn measurements_are_due_after_the_interval() {
        let t0 = Instant::now();
        let mut relax = Relax::default();
        assert!(relax.due(t0));
        relax.observe(t0, 25.0, &[]);
        assert!(!relax.due(t0 + Duration::from_secs(1)));
        assert!(relax.due(t0 + SAMPLE_EVERY));
    }
}
