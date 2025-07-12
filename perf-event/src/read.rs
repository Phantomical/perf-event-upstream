use std::borrow::Cow;
use std::fmt;
use std::iter::FusedIterator;

use crate::ReadFormat;

/// A value read from a single counter.
#[derive(Clone)]
pub(crate) struct CounterValue {
    read_format: ReadFormat,
    value: u64,
    time_enabled: u64,
    time_running: u64,
    id: u64,
    lost: u64,
}

impl CounterValue {
    pub fn from_group_and_entry(group: &GroupValue<'_>, entry: &GroupEntry) -> Self {
        Self {
            read_format: group.read_format - ReadFormat::GROUP,
            value: entry.value,
            time_enabled: group.time_enabled,
            time_running: group.time_running,
            id: entry.id,
            lost: entry.id,
        }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn time_enabled(&self) -> Option<u64> {
        self.read_format
            .contains(ReadFormat::TOTAL_TIME_ENABLED)
            .then_some(self.time_enabled)
    }

    pub fn time_running(&self) -> Option<u64> {
        self.read_format
            .contains(ReadFormat::TOTAL_TIME_RUNNING)
            .then_some(self.time_running)
    }

    pub fn id(&self) -> Option<u64> {
        self.read_format.contains(ReadFormat::ID).then_some(self.id)
    }

    pub fn lost(&self) -> Option<u64> {
        self.read_format
            .contains(ReadFormat::LOST)
            .then_some(self.lost)
    }

    pub(crate) fn parse(data: &[u64], read_format: ReadFormat) -> Result<Self, ParseError> {
        if read_format.contains(ReadFormat::GROUP) {
            return Err(ParseError(
                "attempted to parse a CounterValue with a ReadFormat that has GROUP set",
            ));
        }

        if !(read_format - ReadFormat::all()).is_empty() {
            return Err(ParseError("read_format contains unsupported flags"));
        }

        let mut p = Parser::new(data);
        Ok(Self {
            read_format,
            value: p.parse_u64()?,
            time_enabled: read_format
                .contains(ReadFormat::TOTAL_TIME_ENABLED)
                .then(|| p.parse_u64())
                .transpose()?
                .unwrap_or(0),
            time_running: read_format
                .contains(ReadFormat::TOTAL_TIME_RUNNING)
                .then(|| p.parse_u64())
                .transpose()?
                .unwrap_or(0),
            id: read_format
                .contains(ReadFormat::ID)
                .then(|| p.parse_u64())
                .transpose()?
                .unwrap_or(0),
            lost: read_format
                .contains(ReadFormat::LOST)
                .then(|| p.parse_u64())
                .transpose()?
                .unwrap_or(0),
        })
    }
}

pub(crate) struct GroupValue<'a> {
    read_format: ReadFormat,
    time_enabled: u64,
    time_running: u64,
    data: Cow<'a, [u64]>,
}

// This will be used in a future change
#[allow(dead_code)]
impl<'a> GroupValue<'a> {
    pub fn len(&self) -> usize {
        self.into_iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn time_enabled(&self) -> Option<u64> {
        self.read_format
            .contains(ReadFormat::TOTAL_TIME_ENABLED)
            .then_some(self.time_enabled)
    }

    pub fn time_running(&self) -> Option<u64> {
        self.read_format
            .contains(ReadFormat::TOTAL_TIME_RUNNING)
            .then_some(self.time_running)
    }

    pub fn get(&self, index: usize) -> Option<GroupEntry> {
        self.into_iter().nth(index)
    }

    pub fn get_by_id(&self, id: u64) -> Option<GroupEntry> {
        if !self.read_format.contains(ReadFormat::ID) {
            return None;
        }

        self.into_iter().find(|entry| entry.id() == Some(id))
    }

    pub fn into_owned(self) -> GroupValue<'static> {
        GroupValue {
            read_format: self.read_format,
            time_enabled: self.time_enabled,
            time_running: self.time_running,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    pub(crate) fn parse(data: &'a [u64], read_format: ReadFormat) -> Result<Self, ParseError> {
        if !read_format.contains(ReadFormat::GROUP) {
            return Err(ParseError(
                "attempted to parse a GroupValue with a ReadFormat that does not have GROUP set",
            ));
        }

        if !(read_format - ReadFormat::all()).is_empty() {
            return Err(ParseError("read_format contains unsupported flags"));
        }

        let mut p = Parser::new(data);
        let nr = p.parse_u64()? as usize;
        let time_enabled = read_format
            .contains(ReadFormat::TOTAL_TIME_ENABLED)
            .then(|| p.parse_u64())
            .transpose()?
            .unwrap_or(0);
        let time_running = read_format
            .contains(ReadFormat::TOTAL_TIME_RUNNING)
            .then(|| p.parse_u64())
            .transpose()?
            .unwrap_or(0);

        let element_len = read_format.element_len();
        let data_len = nr.checked_mul(element_len).ok_or(ParseError(
            "number of elements in group read was too large for the data type",
        ))?;
        let data = p.parse_slice(data_len)?;

        Ok(Self {
            read_format,
            time_enabled,
            time_running,
            data: Cow::Borrowed(data),
        })
    }
}

pub(crate) struct GroupEntry {
    read_format: ReadFormat,
    value: u64,
    id: u64,
    lost: u64,
}

impl GroupEntry {
    fn new(config: ReadFormat, slice: &[u64]) -> Self {
        let mut iter = slice.iter().copied();
        let mut read = || {
            iter.next()
                .expect("slice was not the correct size for the configured read_format")
        };

        Self {
            read_format: config,
            value: read(),
            id: config.contains(ReadFormat::ID).then(&mut read).unwrap_or(0),
            lost: config
                .contains(ReadFormat::LOST)
                .then(&mut read)
                .unwrap_or(0),
        }
    }

    // This will be used in a future change
    #[allow(dead_code)]
    /// The value of the counter.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The kernel-assigned unique ID for the counter.
    pub fn id(&self) -> Option<u64> {
        self.read_format.contains(ReadFormat::ID).then_some(self.id)
    }

    /// The number of lost samples of this event.
    pub fn lost(&self) -> Option<u64> {
        self.read_format
            .contains(ReadFormat::LOST)
            .then_some(self.lost)
    }
}

impl<'a> IntoIterator for &'a GroupValue<'_> {
    type Item = GroupEntry;
    type IntoIter = GroupIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        GroupIter::new(self)
    }
}

impl fmt::Debug for GroupEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("GroupEntry");

        dbg.field("value", &self.value);
        if let Some(id) = self.id() {
            dbg.field("id", &id);
        }
        if let Some(lost) = self.lost() {
            dbg.field("lost", &lost);
        }

        dbg.finish()
    }
}

/// Iterator over the entries of a group.
///
/// See [`ReadGroup::entries`].
#[derive(Clone)]
pub(crate) struct GroupIter<'a> {
    iter: std::slice::ChunksExact<'a, u64>,
    read_format: ReadFormat,
}

impl<'a> GroupIter<'a> {
    fn new(group: &'a GroupValue) -> Self {
        Self {
            iter: group.data.chunks_exact(group.read_format.element_len()),
            read_format: group.read_format,
        }
    }
}

impl<'a> Iterator for GroupIter<'a> {
    type Item = GroupEntry;

    fn next(&mut self) -> Option<Self::Item> {
        Some(GroupEntry::new(self.read_format, self.iter.next()?))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }

    fn count(self) -> usize {
        self.iter.count()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        Some(GroupEntry::new(self.read_format, self.iter.nth(n)?))
    }

    fn last(self) -> Option<Self::Item> {
        Some(GroupEntry::new(self.read_format, self.iter.last()?))
    }
}

impl<'a> DoubleEndedIterator for GroupIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        Some(GroupEntry::new(self.read_format, self.iter.next_back()?))
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        Some(GroupEntry::new(self.read_format, self.iter.nth_back(n)?))
    }
}

impl<'a> ExactSizeIterator for GroupIter<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<'a> FusedIterator for GroupIter<'a> {}

impl ReadFormat {
    // The format of a read from a group is like this
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

    pub(crate) const MAX_NON_GROUP_SIZE: usize = Self::all() //
        .difference(Self::GROUP)
        .bits()
        .count_ones() as usize
        + 1;

    /// The size of the common prefix when reading a group.
    pub(crate) fn prefix_len(&self) -> usize {
        1 + (*self & (Self::TOTAL_TIME_ENABLED | Self::TOTAL_TIME_RUNNING))
            .bits()
            .count_ones() as usize
    }

    /// The size of each element when reading a group
    pub(crate) fn element_len(&self) -> usize {
        1 + (*self & (Self::ID | Self::LOST)).bits().count_ones() as usize
    }
}

struct Parser<'a> {
    data: &'a [u64],
}

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u64]) -> Self {
        Self { data }
    }

    pub fn parse_u64(&mut self) -> Result<u64, ParseError> {
        match self.data.split_first() {
            Some((first, rest)) => {
                self.data = rest;
                Ok(*first)
            }
            None => Err(ParseError("unexpected end-of-message")),
        }
    }

    pub fn parse_slice(&mut self, len: usize) -> Result<&'a [u64], ParseError> {
        if len > self.data.len() {
            return Err(ParseError("unexpected end-of-message"));
        }

        let (head, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(head)
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ParseError(&'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParseError {}
