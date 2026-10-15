//! Validate event layouts once and append their fields to bounded Arrow columns.

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    ffi::CStr,
    ptr,
    sync::Arc,
};

use arrow_array::{
    ArrayRef, RecordBatch,
    builder::{Int64Builder, StringBuilder, UInt8Builder, UInt16Builder, UInt64Builder},
};
use arrow_schema::{DataType, Schema};

use crate::ffi::*;

pub(crate) type Result<T> = std::result::Result<T, String>;
pub(crate) type Batch = (String, RecordBatch);

// All borrowed IR pointers below are kept alive by the owned event-class and
// stream references. Native messages are read only while their owner holds a ref.
unsafe fn text(value: *const std::ffi::c_char) -> String {
    if value.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned()
    }
}

unsafe fn members(class: *const bt_field_class) -> Vec<(String, *const bt_field_class)> {
    if class.is_null() {
        return Vec::new();
    }
    unsafe {
        (0..bt_field_class_structure_get_member_count(class))
            .map(|i| {
                let member = bt_field_class_structure_borrow_member_by_index_const(class, i);
                (
                    text(bt_field_class_structure_member_get_name(member)),
                    bt_field_class_structure_member_borrow_field_class_const(member),
                )
            })
            .collect()
    }
}

fn is_type(class: *const bt_field_class, kind: bt_field_class_type) -> bool {
    !class.is_null() && unsafe { bt_field_class_get_type(class) & kind == kind }
}

struct Labels {
    class: *const bt_field_class,
    cached: HashMap<u64, String>,
    names: Vec<String>,
}

impl Labels {
    unsafe fn new(class: *const bt_field_class) -> Self {
        let mut names = unsafe {
            (0..bt_field_class_enumeration_get_mapping_count(class))
                .map(|i| {
                    let mapping =
                        bt_field_class_enumeration_unsigned_borrow_mapping_by_index_const(class, i);
                    text(bt_field_class_enumeration_mapping_get_label(mapping.cast()))
                })
                .collect::<Vec<_>>()
        };
        names.sort();
        Self {
            class,
            cached: HashMap::new(),
            names,
        }
    }

    fn get(&mut self, value: u64, where_: &str) -> Result<&str> {
        if !self.cached.contains_key(&value) {
            let mut labels = ptr::null();
            let mut count = 0;
            let status = unsafe {
                bt_field_class_enumeration_unsigned_get_mapping_labels_for_value(
                    self.class,
                    value,
                    &mut labels,
                    &mut count,
                )
            };
            if status != BT_FIELD_CLASS_ENUMERATION_GET_MAPPING_LABELS_BY_VALUE_STATUS_OK
                || count != 1
            {
                return Err(format!(
                    "{where_} value {value} does not have exactly one label"
                ));
            }
            let label = unsafe { text(*labels) };
            self.cached.insert(value, label);
        }
        Ok(&self.cached[&value])
    }
}

struct Field {
    name: String,
    index: u64,
    presence: Option<u64>,
    labels: Option<Labels>,
}

struct Layout {
    class: *const bt_event_class,
    name: String,
    event_name: String,
    schema: Arc<Schema>,
    fields: Vec<Field>,
    pid: u64,
    tid: u64,
    pid_signed: bool,
    tid_signed: bool,
    outcomes: String,
}

impl Drop for Layout {
    fn drop(&mut self) {
        unsafe { bt_event_class_put_ref(self.class) };
    }
}

impl Layout {
    unsafe fn new(class: *const bt_event_class, name: String, schema: Arc<Schema>) -> Result<Self> {
        unsafe {
            let event_name = text(bt_event_class_get_name(class));
            let stream = bt_event_class_borrow_stream_class_const(class);
            let clock = bt_stream_class_borrow_default_clock_class_const(stream);
            if clock.is_null() {
                return Err(format!("{event_name} events have no clock snapshot"));
            }
            if text(bt_clock_class_get_name(clock)) != "monotonic"
                || bt_clock_class_get_frequency(clock) != 1_000_000_000
            {
                return Err(format!(
                    "{event_name}: analyzer reads only LTTng's default 'monotonic' clock at 1000000000 Hz"
                ));
            }
            let payload = members(bt_event_class_borrow_payload_field_class_const(class));
            let expected = schema
                .fields()
                .iter()
                .skip(3)
                .map(|f| f.name().as_str())
                .collect::<BTreeSet<_>>();
            let missing = expected
                .iter()
                .filter(|n| !payload.iter().any(|(p, _)| p == **n))
                .copied()
                .collect::<Vec<_>>();
            let unknown = payload
                .iter()
                .filter(|(n, _)| {
                    !expected.contains(n.as_str())
                        && !n.strip_prefix("has_").is_some_and(|n| expected.contains(n))
                })
                .map(|(n, _)| n.as_str())
                .collect::<BTreeSet<_>>();
            if !missing.is_empty() || !unknown.is_empty() {
                // Python repr keeps contract diagnostics familiar to callers.
                let repr = |items: Vec<&str>| {
                    format!(
                        "[{}]",
                        items
                            .into_iter()
                            .map(|n| format!("'{n}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                return Err(format!(
                    "{event_name} fields do not match the analyzer schema: missing={} unknown={}",
                    repr(missing),
                    repr(unknown.into_iter().collect())
                ));
            }
            let mut fields = Vec::new();
            let mut outcomes = Vec::new();
            for field in schema.fields().iter().skip(3) {
                let index = payload.iter().position(|(n, _)| n == field.name()).unwrap();
                let class = payload[index].1;
                if !is_type(class, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER) {
                    return Err(format!(
                        "{event_name}.{} is not an unsigned integer field",
                        field.name()
                    ));
                }
                let labelled = is_type(class, BT_FIELD_CLASS_TYPE_UNSIGNED_ENUMERATION);
                if labelled != (field.data_type() == &DataType::Utf8) {
                    return Err(format!(
                        "{event_name}.{} is {}, which does not match the analyzer schema",
                        field.name(),
                        if labelled {
                            "an enumeration"
                        } else {
                            "a plain integer"
                        }
                    ));
                }
                let presence = payload
                    .iter()
                    .position(|(n, _)| n == &format!("has_{}", field.name()));
                if let Some(presence) = presence {
                    if !is_type(payload[presence].1, BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER) {
                        return Err(format!(
                            "{event_name}.has_{} is not an unsigned integer field",
                            field.name()
                        ));
                    }
                }
                let labels = labelled.then(|| Labels::new(class));
                if field.name() == "outcome" {
                    if let Some(labels) = &labels {
                        outcomes = labels.names.clone();
                    }
                }
                fields.push(Field {
                    name: format!("{event_name}.{}", field.name()),
                    index: index as u64,
                    presence: presence.map(|i| i as u64),
                    labels,
                });
            }
            let context =
                members(bt_stream_class_borrow_event_common_context_field_class_const(stream));
            let mut contexts = Vec::new();
            for name in ["vpid", "vtid"] {
                let Some(index) = context.iter().position(|(n, _)| n == name) else {
                    return Err(format!(
                        "{event_name} events have no {name} context; record the trace with `lttng add-context --type {name}`"
                    ));
                };
                let class = context[index].1;
                if !is_type(class, BT_FIELD_CLASS_TYPE_INTEGER) {
                    return Err(format!(
                        "{event_name} has a {name} context that is not an integer"
                    ));
                }
                contexts.push((
                    index as u64,
                    is_type(class, BT_FIELD_CLASS_TYPE_SIGNED_INTEGER),
                ));
            }
            bt_event_class_get_ref(class);
            Ok(Self {
                class,
                name,
                event_name,
                schema,
                fields,
                pid: contexts[0].0,
                tid: contexts[1].0,
                pid_signed: contexts[0].1,
                tid_signed: contexts[1].1,
                outcomes: serde_json::to_string(&outcomes).unwrap(),
            })
        }
    }
}

enum Column {
    U64(UInt64Builder),
    I64(Int64Builder),
    U8(UInt8Builder),
    U16(UInt16Builder),
    Text(StringBuilder),
}

impl Column {
    fn new(kind: &DataType, capacity: usize) -> Result<Self> {
        Ok(match kind {
            DataType::UInt64 => Self::U64(UInt64Builder::with_capacity(capacity)),
            DataType::Int64 => Self::I64(Int64Builder::with_capacity(capacity)),
            DataType::UInt8 => Self::U8(UInt8Builder::with_capacity(capacity)),
            DataType::UInt16 => Self::U16(UInt16Builder::with_capacity(capacity)),
            DataType::Utf8 => Self::Text(StringBuilder::with_capacity(capacity, capacity * 12)),
            _ => return Err(format!("unsupported CTF column type {kind}")),
        })
    }
    fn append(
        &mut self,
        value: Option<u64>,
        labels: Option<&mut Labels>,
        where_: &str,
    ) -> Result<()> {
        macro_rules! integer {
            ($builder:expr, $ty:ty) => {
                match value {
                    None => $builder.append_null(),
                    Some(value) => $builder.append_value(<$ty>::try_from(value).map_err(|_| {
                        format!(
                            "{where_} holds a value that does not fit {}",
                            stringify!($ty)
                        )
                    })?),
                }
            };
        }
        match self {
            Self::U64(b) => integer!(b, u64),
            Self::I64(b) => integer!(b, i64),
            Self::U8(b) => integer!(b, u8),
            Self::U16(b) => integer!(b, u16),
            Self::Text(b) => match value {
                None => b.append_null(),
                Some(v) => b.append_value(labels.unwrap().get(v, where_)?),
            },
        }
        Ok(())
    }
    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::U64(b) => Arc::new(b.finish()),
            Self::I64(b) => Arc::new(b.finish()),
            Self::U8(b) => Arc::new(b.finish()),
            Self::U16(b) => Arc::new(b.finish()),
            Self::Text(b) => Arc::new(b.finish()),
        }
    }
}

struct Output {
    name: String,
    schema: Arc<Schema>,
    columns: Vec<Column>,
    rows: usize,
}
impl Output {
    fn new(layout: &Layout, source: &(String, String), capacity: usize) -> Result<Self> {
        let mut metadata = HashMap::new();
        metadata.insert("capture".into(), source.0.clone());
        metadata.insert("hostname".into(), source.1.clone());
        metadata.insert("outcomes".into(), layout.outcomes.clone());
        let columns = layout
            .schema
            .fields()
            .iter()
            .map(|f| Column::new(f.data_type(), capacity))
            .collect::<Result<_>>()?;
        Ok(Self {
            name: layout.name.clone(),
            schema: Arc::new(layout.schema.as_ref().clone().with_metadata(metadata)),
            columns,
            rows: 0,
        })
    }
    fn finish(&mut self) -> Result<Batch> {
        let arrays = self.columns.iter_mut().map(Column::finish).collect();
        self.rows = 0;
        Ok((
            self.name.clone(),
            RecordBatch::try_new(self.schema.clone(), arrays).map_err(|e| e.to_string())?,
        ))
    }
}

pub(crate) struct Decoder {
    schemas: HashMap<String, Arc<Schema>>,
    layouts: HashMap<usize, Option<Layout>>,
    streams: HashMap<usize, (String, String)>,
    outputs: Vec<Output>,
    output_indices: HashMap<(usize, usize), usize>,
    source_outputs: HashMap<(String, String, String), usize>,
    allowed: Option<BTreeSet<u64>>,
    batch_size: usize,
    discarded_events: u64,
    discarded_packets: u64,
    event_count: u64,
    finished: bool,
    pub(crate) ready: VecDeque<Batch>,
}

impl Drop for Decoder {
    fn drop(&mut self) {
        for (&address, layout) in &self.layouts {
            if layout.is_none() {
                unsafe { bt_event_class_put_ref(address as *const bt_event_class) };
            }
        }
        for &stream in self.streams.keys() {
            unsafe { bt_stream_put_ref(stream as *const bt_stream) };
        }
    }
}

impl Decoder {
    pub(crate) fn new(
        schemas: HashMap<String, Arc<Schema>>,
        allowed: Option<Vec<u64>>,
        batch_size: usize,
    ) -> Result<Self> {
        if batch_size == 0 {
            return Err("batch_size must be positive".into());
        }
        Ok(Self {
            schemas,
            layouts: HashMap::new(),
            streams: HashMap::new(),
            outputs: Vec::new(),
            output_indices: HashMap::new(),
            source_outputs: HashMap::new(),
            allowed: allowed.map(|p| p.into_iter().collect()),
            batch_size,
            discarded_events: 0,
            discarded_packets: 0,
            event_count: 0,
            finished: false,
            ready: VecDeque::new(),
        })
    }

    /// The caller retains the native message until this method returns.
    pub(crate) unsafe fn push(&mut self, message: *const bt_message) -> Result<()> {
        unsafe {
            match bt_message_get_type(message) {
                BT_MESSAGE_TYPE_DISCARDED_EVENTS | BT_MESSAGE_TYPE_DISCARDED_PACKETS => {
                    let mut count = 0;
                    if bt_message_get_type(message) == BT_MESSAGE_TYPE_DISCARDED_EVENTS {
                        if bt_message_discarded_events_get_count(message, &mut count)
                            != BT_PROPERTY_AVAILABILITY_AVAILABLE
                        {
                            count = 1;
                        }
                        self.discarded_events += count;
                    } else {
                        if bt_message_discarded_packets_get_count(message, &mut count)
                            != BT_PROPERTY_AVAILABILITY_AVAILABLE
                        {
                            count = 1;
                        }
                        self.discarded_packets += count;
                    }
                    return Ok(());
                }
                BT_MESSAGE_TYPE_EVENT => {}
                _ => return Ok(()),
            }
            let event = bt_message_event_borrow_event_const(message);
            let class = bt_event_borrow_class_const(event);
            let address = class as usize;
            if !self.layouts.contains_key(&address) {
                let event_name = text(bt_event_class_get_name(class));
                let layout = if let Some((provider, name)) = event_name.split_once(':') {
                    if provider != "moq_trace" && provider != "quic_trace" {
                        None
                    } else {
                        let correct_provider = if name.starts_with("moq_") {
                            "moq_trace"
                        } else {
                            "quic_trace"
                        };
                        let Some(schema) = self
                            .schemas
                            .get(name)
                            .filter(|_| provider == correct_provider)
                        else {
                            return Err(format!(
                                "{event_name} is not an event this analyzer reads; rebuild the relay and analyzer together"
                            ));
                        };
                        Some(Layout::new(class, name.into(), schema.clone())?)
                    }
                } else {
                    None
                };
                // Unknown providers' event classes also need an owned reference:
                // retaining their address alone would permit reuse after a trace ends.
                if layout.is_none() {
                    bt_event_class_get_ref(class);
                }
                self.layouts.insert(address, layout);
            }
            let Some(layout) = self.layouts.get_mut(&address).unwrap() else {
                return Ok(());
            };
            let context = bt_event_borrow_common_context_field_const(event);
            let context_value = |index, signed| -> Result<u64> {
                let field = bt_field_structure_borrow_member_field_by_index_const(context, index);
                if signed {
                    u64::try_from(bt_field_integer_signed_get_value(field))
                        .map_err(|_| "process/thread context cannot be negative".into())
                } else {
                    Ok(bt_field_integer_unsigned_get_value(field))
                }
            };
            let pid = context_value(layout.pid, layout.pid_signed)?;
            let tid = context_value(layout.tid, layout.tid_signed)?;
            if let Some(allowed) = &self.allowed {
                if !allowed.contains(&pid) {
                    return Err(format!(
                        "event {} came from VPID {pid}, which is not in {allowed:?}",
                        layout.event_name
                    ));
                }
            }
            let stream = bt_event_borrow_stream_const(event);
            let stream_address = stream as usize;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.streams.entry(stream_address)
            {
                let trace = bt_stream_borrow_trace_const(stream);
                let capture = bt_trace_get_uid(trace);
                let host = bt_trace_borrow_environment_entry_value_by_name_const(
                    trace,
                    c"hostname".as_ptr(),
                );
                if capture.is_null()
                    || host.is_null()
                    || bt_value_get_type(host) != BT_VALUE_TYPE_STRING
                {
                    return Err(
                        "CTF trace requires a UUID and hostname to identify its processes".into(),
                    );
                }
                entry.insert((text(capture), text(bt_value_string_get(host))));
                bt_stream_get_ref(stream);
            }
            let source = &self.streams[&stream_address];
            let key = (stream_address, address);
            let index = match self.output_indices.get(&key) {
                Some(&index) => index,
                None => {
                    let source_key = (source.0.clone(), source.1.clone(), layout.name.clone());
                    let index = match self.source_outputs.get(&source_key) {
                        Some(&index) => index,
                        None => {
                            let index = self.outputs.len();
                            self.outputs
                                .push(Output::new(layout, source, self.batch_size)?);
                            self.source_outputs.insert(source_key, index);
                            index
                        }
                    };
                    self.output_indices.insert(key, index);
                    index
                }
            };
            let output = &mut self.outputs[index];
            let clock = bt_message_event_borrow_default_clock_snapshot_const(message);
            let emitted = bt_clock_snapshot_get_value(clock);
            let payload = bt_event_borrow_payload_field_const(event);
            let timestamp = bt_field_integer_unsigned_get_value(
                bt_field_structure_borrow_member_field_by_index_const(
                    payload,
                    layout.fields[0].index,
                ),
            );
            if emitted < timestamp {
                return Err(format!(
                    "{} from VPID {pid} was recorded at {emitted} ns, before its timestamp {timestamp} ns; the provider and LTTng must both read CLOCK_MONOTONIC",
                    layout.event_name
                ));
            }
            for (i, value) in [pid, tid, emitted].into_iter().enumerate() {
                output.columns[i].append(Some(value), None, layout.schema.field(i).name())?;
            }
            for (field, column) in layout
                .fields
                .iter_mut()
                .zip(output.columns.iter_mut().skip(3))
            {
                let present = field.presence.is_none_or(|index| {
                    bt_field_integer_unsigned_get_value(
                        bt_field_structure_borrow_member_field_by_index_const(payload, index),
                    ) != 0
                });
                let value = present.then(|| {
                    bt_field_integer_unsigned_get_value(
                        bt_field_structure_borrow_member_field_by_index_const(payload, field.index),
                    )
                });
                column.append(value, field.labels.as_mut(), &field.name)?;
            }
            output.rows += 1;
            self.event_count += 1;
            if output.rows == self.batch_size {
                self.ready.push_back(output.finish()?);
            }
            Ok(())
        }
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.discarded_events != 0 || self.discarded_packets != 0 {
            return Err(format!(
                "LTTng discarded {} events and {} packets",
                self.discarded_events, self.discarded_packets
            ));
        }
        if self.event_count == 0 {
            return Err("CTF trace contains no MoQ or QUIC trace events".into());
        }
        for output in &mut self.outputs {
            if output.rows > 0 {
                self.ready.push_back(output.finish()?);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_narrowing_names_the_event_and_field() {
        let mut column = Column::new(&DataType::Int64, 1).unwrap();
        let error = column
            .append(Some(1 << 63), None, "udp_socket_end.timestamp_ns")
            .unwrap_err();
        assert!(error.contains("udp_socket_end.timestamp_ns"));
        assert!(error.contains("i64"));
    }
}
