//! Own a Babeltrace graph whose sink fills the decoder without Python callbacks.

use crate::{
    decode::{Decoder, Result},
    ffi::*,
};
use std::{
    ffi::{CStr, CString, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

pub(crate) fn error(context: &str) -> String {
    unsafe {
        let error = bt_current_thread_take_error();
        if error.is_null() {
            return context.into();
        }
        let causes = (0..bt_error_get_cause_count(error))
            .map(|i| {
                CStr::from_ptr(bt_error_cause_get_message(bt_error_borrow_cause_by_index(
                    error, i,
                )))
                .to_string_lossy()
                .into_owned()
            })
            .collect::<Vec<_>>();
        bt_error_release(error);
        format!("{context}: {}", causes.join("; "))
    }
}

struct Plugin(*const bt_plugin);
impl Plugin {
    fn find(name: &CStr) -> Result<Self> {
        let mut plugin = ptr::null();
        if unsafe {
            bt_plugin_find(
                name.as_ptr(),
                BT_TRUE as bt_bool,
                BT_TRUE as bt_bool,
                BT_TRUE as bt_bool,
                BT_TRUE as bt_bool,
                BT_TRUE as bt_bool,
                &mut plugin,
            )
        } != BT_PLUGIN_FIND_STATUS_OK
        {
            return Err(error(&format!(
                "cannot load Babeltrace plugin {}",
                name.to_string_lossy()
            )));
        }
        Ok(Self(plugin))
    }
}
impl Drop for Plugin {
    fn drop(&mut self) {
        unsafe { bt_plugin_put_ref(self.0) };
    }
}
struct Value(*mut bt_value);
impl Drop for Value {
    fn drop(&mut self) {
        unsafe { bt_value_put_ref(self.0) };
    }
}

pub(crate) struct State {
    pub(crate) decoder: Decoder,
    pub(crate) error: Option<String>,
}

unsafe extern "C" fn consume(
    iterator: *mut bt_message_iterator,
    data: *mut c_void,
) -> bt_graph_simple_sink_component_consume_func_status {
    // The box stays at a stable address until the graph is dropped. The graph
    // calls this synchronously, on its owner's thread, with no concurrent access.
    let state = unsafe { &mut *data.cast::<State>() };
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        let mut messages = ptr::null_mut();
        let mut count = 0;
        let status = bt_message_iterator_next(iterator, &mut messages, &mut count);
        match status {
            BT_MESSAGE_ITERATOR_NEXT_STATUS_END => {
                return Ok(BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_END);
            }
            BT_MESSAGE_ITERATOR_NEXT_STATUS_AGAIN => {
                return Ok(BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_AGAIN);
            }
            BT_MESSAGE_ITERATOR_NEXT_STATUS_OK => {}
            _ => return Err(error("cannot read CTF messages")),
        }
        let mut failed = None;
        for i in 0..count as usize {
            let message = *messages.add(i);
            if failed.is_none() {
                failed = state.decoder.push(message).err();
            }
            bt_message_put_ref(message);
        }
        match failed {
            Some(error) => Err(error),
            None => Ok(BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_OK),
        }
    }));
    match result {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            state.error = Some(error);
            BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_ERROR
        }
        Err(_) => {
            state.error = Some("native CTF decoder panicked".into());
            BT_GRAPH_SIMPLE_SINK_COMPONENT_CONSUME_FUNC_STATUS_ERROR
        }
    }
}

pub(crate) struct Graph(*mut bt_graph);
impl Drop for Graph {
    fn drop(&mut self) {
        unsafe { bt_graph_put_ref(self.0) };
    }
}
impl Graph {
    pub(crate) fn new(paths: Vec<String>, state: &mut State) -> Result<Self> {
        unsafe {
            let graph = Self(bt_graph_create(1));
            if graph.0.is_null() {
                return Err(error("cannot create Babeltrace graph"));
            }
            let ctf = Plugin::find(c"ctf")?;
            let utils = Plugin::find(c"utils")?;
            let source_class =
                bt_plugin_borrow_source_component_class_by_name_const(ctf.0, c"fs".as_ptr());
            let muxer_class =
                bt_plugin_borrow_filter_component_class_by_name_const(utils.0, c"muxer".as_ptr());
            if source_class.is_null() || muxer_class.is_null() {
                return Err("Babeltrace requires ctf.fs and utils.muxer".into());
            }
            let mut muxer = ptr::null();
            if bt_graph_add_filter_component(
                graph.0,
                muxer_class,
                c"muxer".as_ptr(),
                ptr::null(),
                BT_LOGGING_LEVEL_NONE,
                &mut muxer,
            ) != BT_GRAPH_ADD_COMPONENT_STATUS_OK
            {
                return Err(error("cannot create CTF muxer"));
            }
            for (i, path) in paths.into_iter().enumerate() {
                let params = Value(bt_value_map_create());
                let inputs = Value(bt_value_array_create());
                if params.0.is_null() || inputs.0.is_null() {
                    return Err("cannot allocate CTF source parameters".into());
                }
                let path = CString::new(path).map_err(|_| "CTF path contains a NUL byte")?;
                if bt_value_array_append_string_element(inputs.0, path.as_ptr())
                    != BT_VALUE_ARRAY_APPEND_ELEMENT_STATUS_OK
                    || bt_value_map_insert_entry(params.0, c"inputs".as_ptr(), inputs.0)
                        != BT_VALUE_MAP_INSERT_ENTRY_STATUS_OK
                {
                    return Err(error("cannot set CTF input path"));
                }
                let name = CString::new(format!("source-{i}")).unwrap();
                let mut source = ptr::null();
                if bt_graph_add_source_component(
                    graph.0,
                    source_class,
                    name.as_ptr(),
                    params.0,
                    BT_LOGGING_LEVEL_NONE,
                    &mut source,
                ) != BT_GRAPH_ADD_COMPONENT_STATUS_OK
                {
                    return Err(error("cannot open CTF trace"));
                }
                for port in 0..bt_component_source_get_output_port_count(source) {
                    // The muxer adds an unconnected input after every connection.
                    let last = bt_component_filter_get_input_port_count(muxer) - 1;
                    if bt_graph_connect_ports(
                        graph.0,
                        bt_component_source_borrow_output_port_by_index_const(source, port),
                        bt_component_filter_borrow_input_port_by_index_const(muxer, last),
                        ptr::null_mut(),
                    ) != BT_GRAPH_CONNECT_PORTS_STATUS_OK
                    {
                        return Err(error("cannot connect CTF source"));
                    }
                }
            }
            let mut sink = ptr::null();
            if bt_graph_add_simple_sink_component(
                graph.0,
                c"decode".as_ptr(),
                None,
                Some(consume),
                None,
                (state as *mut State).cast(),
                &mut sink,
            ) != BT_GRAPH_ADD_COMPONENT_STATUS_OK
            {
                return Err(error("cannot create decoder sink"));
            }
            if bt_graph_connect_ports(
                graph.0,
                bt_component_filter_borrow_output_port_by_index_const(muxer, 0),
                bt_component_sink_borrow_input_port_by_index_const(sink, 0),
                ptr::null_mut(),
            ) != BT_GRAPH_CONNECT_PORTS_STATUS_OK
            {
                return Err(error("cannot connect decoder sink"));
            }
            Ok(graph)
        }
    }
    pub(crate) fn step(&mut self) -> Result<bool> {
        match unsafe { bt_graph_run_once(self.0) } {
            BT_GRAPH_RUN_ONCE_STATUS_END => Ok(false),
            BT_GRAPH_RUN_ONCE_STATUS_OK | BT_GRAPH_RUN_ONCE_STATUS_AGAIN => Ok(true),
            _ => Err(error("CTF graph failed")),
        }
    }
}
