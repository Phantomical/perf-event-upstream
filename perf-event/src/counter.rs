use std::borrow::Cow;
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use std::io;
use std::iter::FusedIterator;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::time::Duration;

use perf_event_open_sys::bindings::PERF_IOC_FLAG_GROUP;

use crate::sys::ioctls;
use crate::{check_errno_syscall, ReadFormat};

used_in_docs!(ReadFormat);

/// A counter for one kind of kernel or hardware event.
///
/// A `Counter` represents a single performance monitoring counter. You select
/// what sort of event you'd like to count when the `Counter` is created, then
/// you can enable and disable the counter, call its [`read`] method to
/// retrieve the current count, and reset it to zero.
///
/// A `Counter`'s value is always a `u64`.
///
/// For example, this counts the number of instructions retired (completed)
/// during a call to `println!`.
///
///     use perf_event::Builder;
///
///     fn main() -> std::io::Result<()> {
///         let mut counter = Builder::new().build()?;
///
///         let vec = (0..=51).collect::<Vec<_>>();
///
///         counter.enable()?;
///         println!("{:?}", vec);
///         counter.disable()?;
///
///         println!("{} instructions retired", counter.read()?);
///
///         Ok(())
///     }
///
/// It is often useful to count several different quantities over the same
/// period of time. For example, if you want to measure the average number of
/// clock cycles used per instruction, you must count both clock cycles and
/// instructions retired, for the same range of execution. The [`Group`] type
/// lets you enable, disable, read, and reset any number of counters
/// simultaneously.
///
/// When a counter is dropped, its kernel resources are freed along with it.
///
/// Internally, a `Counter` is just a wrapper around an event file descriptor.
///
/// [`read`]: Counter::read
pub struct Counter {
    /// The file descriptor for this counter, returned by `perf_event_open`.
    ///
    /// When a `Counter` is dropped, this `File` is dropped, and the kernel
    /// removes the counter from any group it belongs to.
    file: File,

    /// The unique id assigned to this counter by the kernel.
    id: u64,

    /// The format info for reading counters.
    read_format: ReadFormat,

    /// If we are a `Group`, then this is the count of how many members we have.
    pub(crate) member_count: u32,
}

impl Counter {
    pub(crate) fn new(file: File, id: u64, read_format: ReadFormat) -> Self {
        Self {
            file,
            id,
            read_format,
            member_count: 1,
        }
    }

    /// Common initialization code shared between counters and groups.
    pub(crate) fn new_internal(file: File, read_format: ReadFormat) -> std::io::Result<Self> {
        let mut counter = Self {
            file,
            id: 0,
            read_format,
            member_count: 1,
        };

        // If we are part of a group then the id is used to find results in the
        // Counts structure. Otherwise, it's just used for debug output.
        let mut id = 0;
        counter.ioctl(|fd| unsafe { ioctls::ID(fd, &mut id) })?;
        counter.id = id;

        Ok(counter)
    }

    /// Return this counter's kernel-assigned unique id.
    ///
    /// This can be useful when iterating over [`Counts`].
    ///
    /// [`Counts`]: struct.Counts.html
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Allow this `Counter` to begin counting its designated event.
    ///
    /// This does not affect whatever value the `Counter` had previously; new
    /// events add to the current count. To clear a `Counter`, use the
    /// [`reset`] method.
    ///
    /// Note that `Group` also has an [`enable`] method, which enables all
    /// its member `Counter`s as a single atomic operation.
    ///
    /// [`reset`]: #method.reset
    /// [`enable`]: struct.Group.html#method.enable
    pub fn enable(&mut self) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::ENABLE(fd, 0) })
    }

    /// Enable all counters in the same group as this one.
    ///
    /// This does not affect whatever value the `Counter` had previously; new
    /// events add to the current count. To clear a counter group, use
    /// [`reset_group`].
    ///
    /// See [`enable`] for the version that only applies to the current
    /// counter.
    ///
    /// [`enable`]: Self::enable
    /// [`reset_group`]: Self::reset_group
    pub fn enable_group(&mut self) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::ENABLE(fd, PERF_IOC_FLAG_GROUP) })
    }

    /// Make this `Counter` stop counting its designated event. Its count is
    /// unaffected.
    ///
    /// Note that `Group` also has a [`disable`] method, which disables all
    /// its member `Counter`s as a single atomic operation.
    ///
    /// [`disable`]: struct.Group.html#method.disable
    pub fn disable(&mut self) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::DISABLE(fd, 0) })
    }

    /// Disable all counters in the same group as this one.
    ///
    /// This does not affect the counter values.
    ///
    /// To disable only this counter use [`disable`].
    ///
    /// [`disable`]: Self::disable
    pub fn disable_group(&mut self) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::DISABLE(fd, PERF_IOC_FLAG_GROUP) })
    }

    /// Reset the value of this `Counter` to zero.
    ///
    /// To reset the value of all counters in the current group use
    /// [`reset_group`](Self::reset_group).
    ///
    /// # Examples
    /// Reset a single counter
    /// ```
    /// use perf_event::events::Hardware;
    /// use perf_event::Builder;
    ///
    /// let mut counter = Builder::new()
    ///     .kind(Hardware::INSTRUCTIONS)
    ///     .build()?;
    /// counter.enable()?;
    /// // ...
    /// counter.disable()?;
    ///
    /// assert_ne!(counter.read()?, 0);
    /// counter.reset()?;
    /// assert_eq!(counter.read()?, 0);
    /// # std::io::Result::Ok(())
    /// ```
    pub fn reset(&mut self) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::RESET(fd, 0) })
    }

    /// Reset the value of all counters in the same group as this one to zero.
    ///
    /// To only reset the value of this counter use [`reset`](Self::reset).
    pub fn reset_group(&mut self) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::RESET(fd, PERF_IOC_FLAG_GROUP) })
    }

    /// Attach an eBPF program to this counter.
    ///
    /// This will only work if this counter was created as a kprobe
    /// tracepoint event.
    ///
    /// This method corresponds to the `IOC_SET_BPF` ioctl.
    pub fn set_bpf(&mut self, bpf: RawFd) -> io::Result<()> {
        self.ioctl(|fd| unsafe { ioctls::SET_BPF(fd, bpf as _) })
            .map(drop)
    }

    /// Helper function for doing ioctls on a counter.
    pub(crate) fn ioctl<F>(&self, ioctl: F) -> io::Result<()>
    where
        F: FnOnce(RawFd) -> libc::c_int,
    {
        check_errno_syscall(|| ioctl(self.as_raw_fd())).map(drop)
    }

    /// Return this `Counter`'s current value as a `u64`.
    ///
    /// Consider using [`read_full`] or (if read_format has the required flags)
    /// [`read_count_and_time`] instead. There are limitations around how
    /// many hardware counters can be on a single CPU at a time. If more
    /// counters are requested than the hardware can support then the kernel
    /// will timeshare them on the hardware. Looking at just the counter value
    /// gives you no indication that this has happened.
    ///
    /// If you would like to read the values for an entire group then you will
    /// need to use [`read_group`] (and set [`ReadFormat::GROUP`]) instead.
    ///
    /// [`read_full`]: Self::read_full
    /// [`read_group`]: Self::read_group
    /// [`read_count_and_time`]: Self::read_count_and_time
    /// [`ReadFormat::GROUP`]: ReadFormat::GROUP
    ///
    /// # Errors
    /// This function may return errors in the following notable cases:
    /// - `ENOSPC` is returned if the `read_format` that this `Counter` was
    ///   built with does not match the format of the data. This can also occur
    ///   if `read_format` contained options not supported by this crate.
    /// - If the counter is part of a group and was unable to be pinned to the
    ///   CPU then reading will return an error with kind [`UnexpectedEof`].
    ///
    /// Other errors are also possible under unexpected conditions (e.g. `EBADF`
    /// if the file descriptor is closed).
    ///
    /// [`UnexpectedEof`]: io::ErrorKind::UnexpectedEof
    ///
    /// # Example
    /// ```
    /// use perf_event::events::Hardware;
    /// use perf_event::Builder;
    ///
    /// let mut builder = Builder::new()
    ///     .kind(Hardware::INSTRUCTIONS);
    /// builder.enabled(true);
    /// let mut counter = builder.build()?;
    ///
    /// let instrs = counter.read()?;
    /// # std::io::Result::Ok(())
    /// ```
    pub fn read(&mut self) -> io::Result<u64> {
        Ok(self.read_full()?.value())
    }

    /// Return all data that this `Counter` is configured to provide.
    ///
    /// The exact fields that are returned within the [`CounterData`] struct
    /// depend on what was specified for `read_format` when constructing this
    /// counter. This method is the only one that gives access to all values
    /// returned by the kernel.
    ///
    /// If this `Counter` was created with [`ReadFormat::GROUP`] then this will
    /// read the entire group but only return the data for this specific
    /// counter.
    ///
    /// # Errors
    /// This function may return errors in the following notable cases:
    /// - `ENOSPC` is returned if the `read_format` that this `Counter` was
    ///   built with does not match the format of the data. This can also occur
    ///   if `read_format` contained options not supported by this crate.
    /// - If the counter is part of a group and was unable to be pinned to the
    ///   CPU then reading will return an error with kind [`UnexpectedEof`].
    ///
    /// Other errors are also possible under unexpected conditions (e.g. `EBADF`
    /// if the file descriptor is closed).
    ///
    /// [`UnexpectedEof`]: io::ErrorKind::UnexpectedEof
    ///
    /// # Example
    /// ```
    /// use std::time::Duration;
    ///
    /// use perf_event::events::Hardware;
    /// use perf_event::{Builder, ReadFormat};
    ///
    /// let mut builder = Builder::new()
    ///     .kind(Hardware::INSTRUCTIONS);
    /// builder
    ///     .read_format(ReadFormat::TOTAL_TIME_RUNNING)
    ///     .enabled(true);
    /// let mut counter = builder.build()?;
    /// // ...
    /// let data = counter.read_full()?;
    /// let instructions = data.value();
    /// let time_running = data.time_running().unwrap();
    /// let ips = instructions as f64 / time_running.as_secs_f64();
    ///
    /// println!("instructions/s: {ips}");
    /// # std::io::Result::Ok(())
    /// ```
    pub fn read_full(&mut self) -> io::Result<CounterValue> {
        if !self.is_group() {
            return self.do_read_single();
        }

        let read_format = self.read_format;
        let prefix_len = read_format.prefix_len();
        let element_len = read_format.element_len();
        let elements = (self.member_count as usize).max(1);
        let mut buf = Vec::with_capacity(prefix_len + elements * element_len);

        let group = self.do_read_group(&mut buf)?;
        let entry = group.get_by_id(self.id).unwrap();
        let value = crate::read::CounterValue::from_group_and_entry(&group, &entry);

        Ok(CounterValue(value))
    }

    /// Return this `Counter`'s current value and timesharing data.
    ///
    /// Some counters are implemented in hardware, and the processor can run
    /// only a fixed number of them at a time. If more counters are requested
    /// than the hardware can support, the kernel timeshares them on the
    /// hardware.
    ///
    /// This method returns a [`CountAndTime`] struct, whose `count` field holds
    /// the counter's value, and whose `time_enabled` and `time_running` fields
    /// indicate how long you had enabled the counter, and how long the counter
    /// was actually scheduled on the processor. This lets you detect whether
    /// the counter was timeshared, and adjust your use accordingly. Times
    /// are reported in nanoseconds.
    ///
    /// # Errors
    /// See the [man page][man] for possible errors when reading from the
    /// counter. This method will also return an error if `read_format` does
    /// not include both [`TOTAL_TIME_ENABLED`] and [`TOTAL_TIME_RUNNING`].
    ///
    /// # Example
    /// ```
    /// # use perf_event::Builder;
    /// # use perf_event::events::Software;
    /// #
    /// # let mut counter = Builder::new().build()?;
    /// let cat = counter.read_count_and_time()?;
    /// if cat.time_running == 0 {
    ///     println!("No data collected.");
    /// } else if cat.time_running < cat.time_enabled {
    ///     // Note: this way of scaling is accurate, but `u128` division
    ///     // is usually implemented in software, which may be slow.
    ///     println!(
    ///         "{} instructions (estimated)",
    ///         (cat.count as u128 * cat.time_enabled as u128 / cat.time_running as u128) as u64
    ///     );
    /// } else {
    ///     println!("{} instructions", cat.count);
    /// }
    /// # std::io::Result::Ok(())
    /// ```
    ///
    /// Note that `Group` also has a [`read`] method, which reads all
    /// its member `Counter`s' values at once.
    ///
    /// [`read`]: crate::Group::read
    /// [`TOTAL_TIME_ENABLED`]: ReadFormat::TOTAL_TIME_ENABLED
    /// [`TOTAL_TIME_RUNNING`]: ReadFormat::TOTAL_TIME_RUNNING
    /// [man]: https://www.mankier.com/2/perf_event_open
    pub fn read_count_and_time(&mut self) -> io::Result<CountAndTime> {
        let data = self.read_full()?;

        Ok(CountAndTime {
            count: data.value(),
            time_enabled: data
                .time_enabled()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "time_enabled was not enabled within read_format",
                    )
                })?
                .as_nanos() as _,
            time_running: data
                .time_running()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "time_running was not enabled within read_format",
                    )
                })?
                .as_nanos() as _,
        })
    }

    /// Read the values of all the counters in the current group.
    ///
    /// Note that unless [`ReadFormat::GROUP`] was specified when building this
    /// `Counter` this will only read the data for the current `Counter`.
    ///
    /// # Errors
    /// This function may return errors in the following notable cases:
    /// - `ENOSPC` is returned if the `read_format` that this `Counter` was
    ///   built with does not match the format of the data. This can also occur
    ///   if `read_format` contained options not supported by this crate.
    /// - If the counter is part of a group and was unable to be pinned to the
    ///   CPU then reading will return an error with kind [`UnexpectedEof`].
    ///
    /// Other errors are also possible under unexpected conditions (e.g. `EBADF`
    /// if the file descriptor is closed).
    ///
    /// [`UnexpectedEof`]: io::ErrorKind::UnexpectedEof
    ///
    /// # Example
    /// Compute the CPI for a region of code:
    /// ```
    /// use perf_event::events::Hardware;
    /// use perf_event::{Builder, ReadFormat};
    ///
    /// let mut instrs = Builder::new(Hardware::INSTRUCTIONS)
    ///     .read_format(ReadFormat::GROUP)
    ///     .build()?;
    /// let mut cycles = Builder::new(Hardware::CPU_CYCLES).build_with_group(&mut instrs)?;
    ///
    /// instrs.enable_group()?;
    /// // ...
    /// instrs.disable_group()?;
    ///
    /// let data = instrs.read_group()?;
    /// let instrs = data[&instrs];
    /// let cycles = data[&cycles];
    ///
    /// println!("CPI: {}", cycles as f64 / instrs as f64);
    /// # std::io::Result::Ok(())
    /// ```
    pub fn read_group(&mut self) -> io::Result<GroupValue> {
        if self.is_group() {
            let mut values = Vec::new();
            let data = self
                .do_read_group(&mut values)?
                .without_data()
                .with_data(Cow::Owned(values));

            Ok(GroupValue::new(data))
        } else {
            Ok(GroupValue::new(self.do_read_single()?.0.into()))
        }
    }

    fn is_group(&self) -> bool {
        self.read_format.contains(ReadFormat::GROUP)
    }

    fn do_read_single(&mut self) -> io::Result<CounterValue> {
        use std::io::Read;
        use std::mem::size_of;

        let mut data = [0u64; ReadFormat::MAX_NON_GROUP_SIZE];

        // SAFETY: It is always safe to cast [u64] to [u8]
        let mut bytes = unsafe { data.align_to_mut::<u8>().1 };
        let len = self.file.read(&mut bytes)?;

        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "the kernel was unable to schedule the counter or group",
            ));
        }

        assert!(
            len % size_of::<u64>() == 0,
            "kernel returned a length that was not a multiple of 8"
        );

        let data = &data[..len / size_of::<u64>()];
        let value = crate::read::CounterValue::parse(data, self.read_format) //
            .map_err(io::Error::other)?;

        Ok(CounterValue(value))
    }

    /// Actual read implementation for when `ReadFormat::GROUP` is set.
    fn do_read_group<'a>(
        &mut self,
        data: &'a mut Vec<u64>,
    ) -> io::Result<crate::read::GroupValue<'a>> {
        use std::io::Read;
        use std::mem::size_of;

        // The general structure format looks like this, depending on what
        // read_format flags were enabled.
        //
        // struct read_format {
        //     u64 nr;            /* The number of events */
        //     u64 time_enabled;  /* if PERF_FORMAT_TOTAL_TIME_ENABLED */
        //     u64 time_running;  /* if PERF_FORMAT_TOTAL_TIME_RUNNING */
        //     struct {
        //         u64 value;     /* The value of the event */
        //         u64 id;        /* if PERF_FORMAT_ID */
        //         u64 lost;      /* if PERF_FORMAT_LOST */
        //     } values[nr];
        // };
        let read_format = self.read_format;
        let prefix_len = read_format.prefix_len();
        let element_len = read_format.element_len();

        let mut elements = (self.member_count as usize).max(1);
        data.resize(prefix_len + elements * element_len, 0u64);

        // Backoff loop to try and get the correct size.
        //
        // There's no way to know when new counters are added to the current
        // group, so to make sure reads succeed we expand the buffer whenever
        // we get ENOSPC until the read completes.
        //
        // The next time around self.member_count will be set to the correct
        // count and we won't need to go through this loop multiple times.
        let len = loop {
            // SAFETY: It is always safe to cast [u64] to [u8]
            let bytes = unsafe { data.align_to_mut::<u8>().1 };
            match self.file.read(bytes) {
                Ok(len) => break len,
                Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                    elements *= 2;
                    data.resize((prefix_len + elements * element_len) * size_of::<u64>(), 0);
                }
                Err(e) => return Err(e),
            }
        };

        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "the kernel was unable to schedule the counter or group",
            ));
        }

        data.truncate(len);
        let value = crate::read::GroupValue::parse(&*data, read_format) //
            .map_err(io::Error::other)?;

        self.member_count = data
            .len()
            .try_into()
            .expect("group had more than u32::MAX elements");

        Ok(value)
    }
}

impl std::fmt::Debug for Counter {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            fmt,
            "Counter {{ fd: {}, id: {} }}",
            self.file.as_raw_fd(),
            self.id
        )
    }
}

impl AsRawFd for Counter {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl IntoRawFd for Counter {
    fn into_raw_fd(self) -> RawFd {
        self.file.into_raw_fd()
    }
}

/// The data retrieved by reading from a [`Counter`].
#[derive(Clone)]
pub struct CounterValue(crate::read::CounterValue);

impl CounterValue {
    /// The counter value.
    ///
    /// The meaning of this field depends on how the counter was configured when
    /// it was built; see ['Builder'].
    pub fn value(&self) -> u64 {
        self.0.value()
    }

    /// How long this counter was enabled by the program.
    ///
    /// This will be present if [`ReadFormat::TOTAL_TIME_ENABLED`] was
    /// specified in `read_format` when the counter was built.
    pub fn time_enabled(&self) -> Option<Duration> {
        self.0.time_enabled().map(Duration::from_nanos)
    }

    /// How long the kernel actually ran this counter.
    ///
    /// If `time_enabled == time_running` then the counter ran for the entire
    /// period it was enabled, without interruption. Otherwise, the counter
    /// shared the underlying hardware with others and you should adjust its
    /// value accordingly.
    ///
    /// This will be present if [`ReadFormat::TOTAL_TIME_RUNNING`] was
    /// specified in `read_format` when the counter was built.
    pub fn time_running(&self) -> Option<Duration> {
        self.0.time_running().map(Duration::from_nanos)
    }

    /// The number of lost samples of this event.
    ///
    /// This will be present if [`ReadFormat::LOST`] was specified in
    /// `read_format` when the counter was built.
    pub fn lost(&self) -> Option<u64> {
        self.0.lost()
    }
}

impl fmt::Debug for CounterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("CounterValue");

        dbg.field("value", &self.0.value());
        if let Some(time_enabled) = self.0.time_enabled() {
            dbg.field("time_enabled", &time_enabled);
        }
        if let Some(time_running) = self.0.time_running() {
            dbg.field("time_running", &time_running);
        }
        dbg.field("id", &self.0.id());
        dbg.field("lost", &self.0.lost());
        dbg.finish_non_exhaustive()
    }
}

/// The value of a counter, along with timesharing data.
///
/// Some counters are implemented in hardware, and the processor can run
/// only a fixed number of them at a time. If more counters are requested
/// than the hardware can support, the kernel timeshares them on the
/// hardware.
///
/// This struct holds the value of a counter, together with the time it was
/// enabled, and the proportion of that for which it was actually running.
#[repr(C)]
pub struct CountAndTime {
    /// The counter value.
    ///
    /// The meaning of this field depends on how the counter was configured when
    /// it was built; see ['Builder'].
    pub count: u64,

    /// How long this counter was enabled by the program, in nanoseconds.
    pub time_enabled: u64,

    /// How long the kernel actually ran this counter, in nanoseconds.
    ///
    /// If `time_enabled == time_running`, then the counter ran for the entire
    /// period it was enabled, without interruption. Otherwise, the counter
    /// shared the underlying hardware with others, and you should prorate its
    /// value accordingly.
    pub time_running: u64,
}

#[derive(Clone)]
pub struct GroupValue {
    pub(crate) data: crate::read::GroupValue<'static>,
    skip_first: bool,
}

impl GroupValue {
    pub(crate) fn new(data: crate::read::GroupValue<'static>) -> Self {
        Self {
            data,
            skip_first: false,
        }
    }

    /// Return the number of counters this `GroupData` holds results for.
    pub fn len(&self) -> usize {
        self.iter().len()
    }

    /// Whether this `GroupData` is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The duration for which the group was enabled.
    ///
    /// This will only be present if [`TOTAL_TIME_ENABLED`] was passed to
    /// [`read_format`].
    ///
    /// [`TOTAL_TIME_ENABLED`]: ReadFormat::TOTAL_TIME_ENABLED
    /// [`read_format`]: Builder::read_format
    pub fn time_enabled(&self) -> Option<Duration> {
        self.data.time_enabled().map(Duration::from_nanos)
    }

    /// The duration for which the group was scheduled on the CPU.
    ///
    /// This will only be present if [`TOTAL_TIME_RUNNING`] was passed to
    /// [`read_format`].
    ///
    /// [`TOTAL_TIME_RUNNING`]: ReadFormat::TOTAL_TIME_RUNNING
    /// [`read_format`]: Builder::read_format
    pub fn time_running(&self) -> Option<Duration> {
        self.data.time_running().map(Duration::from_nanos)
    }

    /// Get the entry for `member` in `self`, or `None` if `member` is not
    /// present.
    ///
    /// `member` can be either a `Counter` or a `Group`.
    ///
    /// If you know the counter is in the group then you can access the count
    /// via indexing.
    /// ```
    /// use perf_event::events::Hardware;
    /// use perf_event::{Builder, Group};
    ///
    /// let mut group = Group::new()?;
    /// let instrs = Builder::new(Hardware::INSTRUCTIONS).build_with_group(&mut group)?;
    /// let cycles = Builder::new(Hardware::CPU_CYCLES).build_with_group(&mut group)?;
    /// group.enable()?;
    /// // ...
    /// let counts = group.read()?;
    /// let instrs = counts[&instrs];
    /// let cycles = counts[&cycles];
    /// # std::io::Result::Ok(())
    /// ```
    pub fn get(&self, member: &Counter) -> Option<GroupEntry> {
        self.data.get_by_id(member.id()).map(GroupEntry)
    }

    /// Return an iterator over all entries in `self`.
    ///
    /// For compatibility reasons, if this `GroupData` was returned by reading
    /// from a [`Group`] then the iterator will skip the group counter itself.
    /// Normally this is what you want since the [`Group`] is usually a dummy
    /// counter. This does not apply if this `GroupData` was returned from a
    /// [`read_group`](Counter::read_group) call on a [`Counter`].
    ///
    /// # Example
    /// ```
    /// # use perf_event::Group;
    /// # let mut group = Group::new()?;
    /// let data = group.read()?;
    /// for entry in &data {
    ///     println!("Counter with id {} has value {}", entry.id(), entry.value());
    /// }
    /// # std::io::Result::Ok(())
    /// ```
    pub fn iter(&self) -> GroupIter {
        let mut iter = self.iter_with_group();
        if self.skip_first {
            let _ = iter.next();
        }
        iter
    }

    fn iter_with_group(&self) -> GroupIter {
        GroupIter((&self.data).into_iter())
    }

    /// Mark that the first counter in this group is a `Group` and should not be
    /// included when iterating over this `GroupData` instance.
    pub(crate) fn skip_group(&mut self) {
        self.skip_first = true;
    }
}

/// Individual entry for a counter returned by [`Group::read`].
#[derive(Copy, Clone)]
pub struct GroupEntry(pub(crate) crate::read::GroupEntry);

impl GroupEntry {
    /// The value of the counter.
    pub fn value(&self) -> u64 {
        self.0.value()
    }

    /// The kernel-assigned unique id of the counter that was read.
    pub fn id(&self) -> u64 {
        self.0.id().expect("group entry did not have an id")
    }

    /// The number of lost samples for this event.
    pub fn lost(&self) -> Option<u64> {
        self.0.lost()
    }
}

impl std::ops::Index<&Counter> for GroupValue {
    type Output = u64;

    fn index(&self, ctr: &Counter) -> &u64 {
        self.data
            .get_value_by_id(ctr.id())
            .unwrap_or_else(|| panic!("group contained no counter with id {}", ctr.id()))
    }
}

impl fmt::Debug for GroupValue {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        struct GroupEntries<'a>(&'a GroupValue);

        impl fmt::Debug for GroupEntries<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        let mut dbg = fmt.debug_struct("GroupData");

        if let Some(time_enabled) = self.time_enabled() {
            dbg.field("time_enabled", &time_enabled.as_nanos());
        }

        if let Some(time_running) = self.time_running() {
            dbg.field("time_running", &time_running.as_nanos());
        }

        dbg.field("entries", &GroupEntries(self));
        dbg.finish()
    }
}

impl<'a> IntoIterator for &'a GroupValue {
    type IntoIter = GroupIter<'a>;
    type Item = <GroupIter<'a> as Iterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for GroupEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("GroupEntry");
        dbg.field("value", &self.value());
        dbg.field("id", &self.id());

        if let Some(lost) = self.lost() {
            dbg.field("lost", &lost);
        }

        dbg.finish_non_exhaustive()
    }
}

/// Iterator over the entries contained within [`GroupData`].
#[derive(Clone)]
pub struct GroupIter<'a>(crate::read::GroupIter<'a>);

impl<'a> Iterator for GroupIter<'a> {
    type Item = GroupEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(GroupEntry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    fn count(self) -> usize {
        self.0.count()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth(n).map(GroupEntry)
    }

    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }
}

impl<'a> DoubleEndedIterator for GroupIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back().map(GroupEntry)
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.0.nth_back(n).map(GroupEntry)
    }
}

impl<'a> ExactSizeIterator for GroupIter<'a> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> FusedIterator for GroupIter<'a> {}
