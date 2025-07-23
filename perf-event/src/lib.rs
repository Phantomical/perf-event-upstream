//! A performance monitoring API for Linux.
//!
//! This crate provides access to processor and kernel counters for things like
//! instruction completions, cache references and misses, branch predictions,
//! context switches, page faults, and so on.
//!
//! For example, to compare the number of clock cycles elapsed with the number
//! of instructions completed during one call to `println!`:
//!
//!     use perf_event::{Builder, Group};
//!     use perf_event::events::Hardware;
//!
//!     fn main() -> std::io::Result<()> {
//!         // A `Group` lets us enable and disable several counters atomically.
//!         let mut group = Group::new()?;
//!         let cycles = Builder::new().group(&mut group).kind(Hardware::CPU_CYCLES).build()?;
//!         let insns = Builder::new().group(&mut group).kind(Hardware::INSTRUCTIONS).build()?;
//!
//!         let vec = (0..=51).collect::<Vec<_>>();
//!
//!         group.enable()?;
//!         println!("{:?}", vec);
//!         group.disable()?;
//!
//!         let counts = group.read()?;
//!         println!("cycles / instructions: {} / {} ({:.2} cpi)",
//!                  counts[&cycles],
//!                  counts[&insns],
//!                  (counts[&cycles] as f64 / counts[&insns] as f64));
//!
//!         Ok(())
//!     }
//!
//! This crate is built on top of the Linux [`perf_event_open`][man] system
//! call; that documentation has the authoritative explanations of exactly what
//! all the counters mean.
//!
//! There are two main types for measurement:
//!
//! -   A [`Counter`] is an individual counter. Use [`Builder`] to
//!     construct one.
//!
//! -   A [`Group`] is a collection of counters that can be enabled and
//!     disabled atomically, so that they cover exactly the same period of
//!     execution, allowing meaningful comparisons of the individual values.
//!
//! If you're familiar with the kernel API already:
//!
//! -   A `Builder` holds the arguments to a `perf_event_open` call:
//!     a `struct perf_event_attr` and a few other fields.
//!
//! -   `Counter` and `Group` objects are just event file descriptors, together
//!     with their kernel id numbers, and some other details you need to
//!     actually use them. They're different types because they yield different
//!     types of results, and because you can't retrieve a `Group`'s counts
//!     without knowing how many members it has.
//!
//! ### Call for PRs
//!
//! Linux's `perf_event_open` API can report all sorts of things this crate
//! doesn't yet understand: stack traces, logs of executable and shared library
//! activity, tracepoints, kprobes, uprobes, and so on. And beyond the counters
//! in the kernel header files, there are others that can only be found at
//! runtime by consulting `sysfs`, specific to particular processors and
//! devices. For example, modern Intel processors have counters that measure
//! power consumption in Joules.
//!
//! If you find yourself in need of something this crate doesn't support, please
//! consider submitting a pull request.
//!
//! [man]: http://man7.org/linux/man-pages/man2/perf_event_open.2.html

#![deny(missing_docs)]

/// A helper macro for silencing warnings when a type is only implemented so
/// that it can be linked in the docs.
macro_rules! used_in_docs {
    ($t:ident) => {
        const _: () = {
            // Using a module here means that this macro can accept any identifier that
            // would normally be used in an import statement.
            mod use_item {
                #[allow(unused_imports)]
                use super::$t;
            }
        };
    };
}

use perf_event_open_sys::bindings::perf_event_attr;
use std::fs::File;
use std::io::{self, Read};
use std::os::raw::{c_int, c_uint};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

pub mod events;

#[cfg(feature = "hooks")]
pub mod hooks;

mod builder;
mod counter;
mod flags;
mod read;

// When the `"hooks"` feature is not enabled, call directly into
// `perf-event-open-sys`.
#[cfg(not(feature = "hooks"))]
use perf_event_open_sys as sys;

// When the `"hooks"` feature is enabled, `sys` functions allow for
// interposed functions that provide simulated results for testing.
#[cfg(feature = "hooks")]
use hooks::sys;

pub use crate::builder::Builder;
use crate::counter::GroupValue;
pub use crate::counter::{CountAndTime, Counter, CounterValue};
pub use crate::flags::{Clock, ReadFormat, SampleBranchFlag, SampleSkid};

/// A group of counters that can be managed as a unit.
///
/// A `Group` represents a group of [`Counter`]s that can be enabled,
/// disabled, reset, or read as a single atomic operation. This is necessary if
/// you want to compare counter values, produce ratios, and so on, since those
/// operations are only meaningful on counters that cover exactly the same
/// period of execution.
///
/// A `Counter` is placed in a group when it is created via the
/// [`Builder::build_with_group`] method. A `Group`'s [`read`] method returns
/// values of all its member counters at once as a [`GroupData`] value, which
/// can be indexed by `Counter` to retrieve a specific value.
///
/// The lifetime of a `Group` and its associated `Counter`s are independent:
/// you can drop them in any order and they will continue to work. A `Counter`
/// will continue to work after the `Group` is dropped. If a `Counter` is
/// dropped first then it will simply be removed from the `Group`.
///
/// Enabling or disabling a `Group` affects each `Counter` that belongs to it.
/// Subsequent reads from the `Counter` will not reflect activity while the
/// `Group` was disabled, unless the `Counter` is re-enabled individually.
///
/// ## Limits on group size
///
/// Hardware counters are implemented using special-purpose registers on the
/// processor, of which there are only a fixed number. (For example, an Intel
/// high-end laptop processor from 2015 has four such registers per virtual
/// processor.) Without using groups, if you request more hardware counters than
/// the processor can actually support, a complete count isn't possible, but the
/// kernel will rotate the processor's real registers amongst the measurements
/// you've requested to at least produce a sample.
///
/// But since the point of a counter group is that its members all cover exactly
/// the same period of time, this tactic can't be applied to support large
/// groups. If the kernel cannot schedule a group, its counters remain zero. I
/// think you can detect this situation by comparing the group's
/// [`time_enabled`] and [`time_running`] values. If the [`pinned`] option is
/// set then you will also be able to detect this by [`read`] returning an error
/// with kind [`UnexpectedEof`].
///
/// According to the `perf_list(1)` man page, you may be able to free up a
/// hardware counter by disabling the kernel's NMI watchdog, which reserves one
/// for detecting kernel hangs:
///
/// ```text
/// $ echo 0 > /proc/sys/kernel/nmi_watchdog
/// ```
///
/// You can reenable the watchdog when you're done like this:
///
/// ```text
/// $ echo 1 > /proc/sys/kernel/nmi_watchdog
/// ```
///
/// [`read`]: Self::read
/// [`pinned`]: Builder::pinned
/// [`UnexpectedEof`]: io::ErrorKind::UnexpectedEof
///
/// # Examples
/// Compute the average cycles-per-instruction (CPI) for a call to `println!`:
/// ```
/// use perf_event::events::Hardware;
/// use perf_event::{Builder, Group};
///
/// let mut group = Group::new()?;
/// let cycles = group.add(&Builder::new(Hardware::CPU_CYCLES))?;
/// let insns = group.add(&Builder::new(Hardware::INSTRUCTIONS))?;
///
/// let vec = (0..=51).collect::<Vec<_>>();
///
/// group.enable()?;
/// println!("{:?}", vec);
/// group.disable()?;
///
/// let counts = group.read()?;
/// println!(
///     "cycles / instructions: {} / {} ({:.2} cpi)",
///     counts[&cycles],
///     counts[&insns],
///     (counts[&cycles] as f64 / counts[&insns] as f64)
/// );
/// # std::io::Result::Ok(())
/// ```
///
/// [`read`]: Group::read
/// [`time_enabled`]: GroupData::time_enabled
/// [`time_running`]: GroupData::time_running
#[derive(Debug)]
pub struct Group(pub(crate) Counter);

/// A collection of counts from a [`Group`] of counters.
///
/// This is the type returned by calling [`read`] on a [`Group`].
/// You can index it with a reference to a specific `Counter`:
///
///     # fn main() -> std::io::Result<()> {
///     # use perf_event::{Builder, Group};
///     # let mut group = Group::new()?;
///     # let cycles = Builder::new().group(&mut group).build()?;
///     # let insns = Builder::new().group(&mut group).build()?;
///     let counts = group.read()?;
///     println!("cycles / instructions: {} / {} ({:.2} cpi)",
///              counts[&cycles],
///              counts[&insns],
///              (counts[&cycles] as f64 / counts[&insns] as f64));
///     # Ok(()) }
///
/// Or you can iterate over the results it contains:
///
///     # fn main() -> std::io::Result<()> {
///     # use perf_event::Group;
///     # let counts = Group::new()?.read()?;
///     for (id, value) in &counts {
///         println!("Counter id {} has value {}", id, value);
///     }
///     # Ok(()) }
///
/// The `id` values produced by this iteration are internal identifiers assigned
/// by the kernel. You can use the [`Counter::id`] method to find a
/// specific counter's id.
///
/// For some kinds of events, the kernel may use timesharing to give all
/// counters access to scarce hardware registers. You can see how long a group
/// was actually running versus the entire time it was enabled using the
/// `time_enabled` and `time_running` methods:
///
///     # fn main() -> std::io::Result<()> {
///     # use perf_event::{Builder, Group};
///     # let mut group = Group::new()?;
///     # let insns = Builder::new().group(&mut group).build()?;
///     # let counts = group.read()?;
///     let scale = counts.time_enabled() as f64 /
///                 counts.time_running() as f64;
///     for (id, value) in &counts {
///         print!("Counter id {} has value {}",
///                id, (*value as f64 * scale) as u64);
///         if scale > 1.0 {
///             print!(" (estimated)");
///         }
///         println!();
///     }
///
///     # Ok(()) }
///
/// [`read`]: Group::read
pub struct Counts {
    // Raw results from the `read`.
    data: Vec<u64>,
}

impl Group {
    /// Construct a new, empty `Group`.
    ///
    /// The resulting `Group` is only suitable for observing the current process
    /// on any CPU. If you need to build a `Group` with different settings you
    /// will need to use [`Builder::build_group`].
    pub fn new() -> io::Result<Group> {
        Self::builder().build_group()
    }

    /// Construct a [Builder] preconfigured for creating a `Group`.
    ///
    /// Specifically, this creates a builder with the [`Software::DUMMY`] event
    /// and with [`read_format`] set to `GROUP | ID | TOTAL_TIME_ENABLED |
    /// TOTAL_TIME_RUNNING`. If you override [`read_format`] you will need to
    /// ensure that [`ReadFormat::GROUP`] is set, otherwise [`build_group`] will
    /// return an error.
    ///
    /// Note that any counter added to this group must observe the same set of
    /// CPUs and processes as the group itself. That means if you configure the
    /// group to observe a single CPU then the members of the group must also be
    /// configured to only observe a single CPU, the same applies when choosing
    /// target processes. Failing to follow this will result in an error when
    /// adding the counter to the group.
    ///
    /// [`read_format`]: Builder::read_format
    /// [`build_group`]: Builder::build_group
    pub fn builder() -> Builder<'static> {
        let mut builder = Builder::new();
        builder.read_format(
            ReadFormat::GROUP
                | ReadFormat::TOTAL_TIME_ENABLED
                | ReadFormat::TOTAL_TIME_RUNNING
                | ReadFormat::ID,
        );

        builder
    }

    /// Access the internal counter for this group.
    pub fn as_counter(&self) -> &Counter {
        &self.0
    }

    /// Mutably access the internal counter for this group.
    pub fn as_counter_mut(&mut self) -> &mut Counter {
        &mut self.0
    }

    /// Convert this `Group` into its internal counter.
    pub fn into_counter(self) -> Counter {
        self.0
    }

    /// Return this group's kernel-assigned unique id.
    pub fn id(&self) -> u64 {
        self.0.id()
    }

    /// Allow all `Counter`s in this `Group` to begin counting their designated
    /// events, as a single atomic operation.
    ///
    /// This does not affect whatever values the `Counter`s had previously; new
    /// events add to the current counts. To clear the `Counter`s, use the
    /// [`reset`] method.
    ///
    /// [`reset`]: #method.reset
    pub fn enable(&mut self) -> io::Result<()> {
        self.0.enable_group()
    }

    /// Make all `Counter`s in this `Group` stop counting their designated
    /// events, as a single atomic operation. Their counts are unaffected.
    pub fn disable(&mut self) -> io::Result<()> {
        self.0.disable_group()
    }

    /// Reset all `Counter`s in this `Group` to zero, as a single atomic operation.
    pub fn reset(&mut self) -> io::Result<()> {
        self.0.reset_group()
    }

    /// Construct a new counter as a part of this group.
    ///
    /// # Example
    /// ```
    /// use perf_event::events::Hardware;
    /// use perf_event::{Builder, Group};
    ///
    /// let mut group = Group::new()?;
    /// let counter = group.add(&Builder::new(Hardware::INSTRUCTIONS).any_cpu());
    /// #
    /// # std::io::Result::Ok(())
    /// ```
    pub fn add(&mut self, builder: &Builder) -> io::Result<Counter> {
        builder.build_with_group(self)
    }

    /// Return the values of all the `Counter`s in this `Group` as a [`Counts`]
    /// value.
    ///
    /// A `Counts` value is a map from specific `Counter`s to their values. You
    /// can find a specific `Counter`'s value by indexing:
    ///
    /// ```ignore
    /// let mut group = Group::new()?;
    /// let counter1 = Builder::new().group(&mut group).kind(...).build()?;
    /// let counter2 = Builder::new().group(&mut group).kind(...).build()?;
    /// ...
    /// let counts = group.read()?;
    /// println!("Rhombus inclinations per taxi medallion: {} / {} ({:.0}%)",
    ///          counts[&counter1],
    ///          counts[&counter2],
    ///          (counts[&counter1] as f64 / counts[&counter2] as f64) * 100.0);
    /// ```
    ///
    /// [`Counts`]: struct.Counts.html
    pub fn read(&mut self) -> io::Result<GroupValue> {
        self.0.read_group()
    }
}

impl AsRawFd for Group {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for Group {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl AsRef<Counter> for &'_ Group {
    fn as_ref(&self) -> &Counter {
        &self.0
    }
}

impl AsMut<Counter> for &'_ mut Group {
    fn as_mut(&mut self) -> &mut Counter {
        &mut self.0
    }
}

impl Counts {
    /// Return the number of counters this `Counts` holds results for.
    #[allow(clippy::len_without_is_empty)] // Groups are never empty.
    pub fn len(&self) -> usize {
        self.data[0] as usize
    }

    /// Return the number of nanoseconds the `Group` was enabled that
    /// contributed to this `Counts`' contents.
    pub fn time_enabled(&self) -> u64 {
        self.data[1]
    }

    /// Return the number of nanoseconds the `Group` was actually collecting
    /// counts that contributed to this `Counts`' contents.
    pub fn time_running(&self) -> u64 {
        self.data[2]
    }

    /// Return a range of indexes covering the count and id of the `n`'th counter.
    fn nth_index(n: usize) -> std::ops::Range<usize> {
        let base = 3 + 2 * n;
        base..base + 2
    }

    /// Return the id and count of the `n`'th counter. This returns a reference
    /// to the count, for use by the `Index` implementation.
    fn nth_ref(&self, n: usize) -> (u64, &u64) {
        let id_val = &self.data[Counts::nth_index(n)];

        // (id, &value)
        (id_val[1], &id_val[0])
    }
}

/// An iterator over the counter values in a [`Counts`], returned by
/// [`Group::read`].
///
/// Each item is a pair `(id, &value)`, where `id` is the number assigned to the
/// counter by the kernel (see `Counter::id`), and `value` is that counter's
/// value.
///
/// [`Counts`]: struct.Counts.html
/// [`Counter::id`]: struct.Counter.html#method.id
/// [`Group::read`]: struct.Group.html#method.read
pub struct CountsIter<'c> {
    counts: &'c Counts,
    next: usize,
}

impl<'c> Iterator for CountsIter<'c> {
    type Item = (u64, &'c u64);
    fn next(&mut self) -> Option<(u64, &'c u64)> {
        if self.next >= self.counts.len() {
            return None;
        }
        let result = self.counts.nth_ref(self.next);
        self.next += 1;
        Some(result)
    }
}

impl<'c> IntoIterator for &'c Counts {
    type Item = (u64, &'c u64);
    type IntoIter = CountsIter<'c>;
    fn into_iter(self) -> CountsIter<'c> {
        CountsIter {
            counts: self,
            next: 1, // skip the `Group` itself, it's just a dummy.
        }
    }
}

impl Counts {
    /// Return the value recorded for `member` in `self`, or `None` if `member`
    /// is not present.
    ///
    /// If you know that `member` is in the group, you can simply index:
    ///
    ///     # fn main() -> std::io::Result<()> {
    ///     # use perf_event::{Builder, Group};
    ///     # let mut group = Group::new()?;
    ///     # let cycle_counter = Builder::new().group(&mut group).build()?;
    ///     # let counts = group.read()?;
    ///     let cycles = counts[&cycle_counter];
    ///     # Ok(()) }
    pub fn get(&self, member: &Counter) -> Option<&u64> {
        self.into_iter()
            .find(|&(id, _)| id == member.id())
            .map(|(_, value)| value)
    }

    /// Return an iterator over the counts in `self`.
    ///
    ///     # fn main() -> std::io::Result<()> {
    ///     # use perf_event::Group;
    ///     # let counts = Group::new()?.read()?;
    ///     for (id, value) in &counts {
    ///         println!("Counter id {} has value {}", id, value);
    ///     }
    ///     # Ok(()) }
    ///
    /// Each item is a pair `(id, &value)`, where `id` is the number assigned to
    /// the counter by the kernel (see `Counter::id`), and `value` is that
    /// counter's value.
    pub fn iter(&self) -> CountsIter {
        <&Counts as IntoIterator>::into_iter(self)
    }
}

impl std::ops::Index<&Counter> for Counts {
    type Output = u64;
    fn index(&self, index: &Counter) -> &u64 {
        self.get(index).unwrap()
    }
}

impl std::fmt::Debug for Counts {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_map().entries(self.into_iter()).finish()
    }
}

/// A type whose values can be safely accessed as a slice of bytes.
///
/// # Safety
///
/// `Self` must be a type such that storing a value in memory
/// initializes all the bytes of that memory, so that
/// `slice_as_bytes_mut` can never expose uninitialized bytes to the
/// caller.
unsafe trait SliceAsBytesMut: Sized {
    fn slice_as_bytes_mut(slice: &mut [Self]) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                slice.as_mut_ptr() as *mut u8,
                std::mem::size_of_val(slice),
            )
        }
    }
}

unsafe impl SliceAsBytesMut for u64 {}

/// Produce an `io::Result` from an errno-style system call.
///
/// An 'errno-style' system call is one that reports failure by returning -1 and
/// setting the C `errno` value when an error occurs.
fn check_errno_syscall<F, R>(f: F) -> io::Result<R>
where
    F: FnOnce() -> R,
    R: PartialOrd + Default,
{
    let result = f();
    if result < R::default() {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[test]
fn simple_build() {
    Builder::new()
        .build()
        .expect("Couldn't build default Counter");
}

#[test]
#[cfg(target_os = "linux")]
fn test_error_code_is_correct() {
    // This configuration should always result in EINVAL
    let builder = Builder::new()
        // CPU_CLOCK is literally always supported so we don't have to worry
        // about test failures when in VMs.
        .kind(events::Software::CPU_CLOCK)
        // There should _hopefully_ never be a system with this many CPUs.
        .one_cpu(i32::MAX as usize);

    match builder.build() {
        Ok(_) => panic!("counter construction was not supposed to succeed"),
        Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EINVAL)),
    }
}
