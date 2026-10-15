//! Native, bounded CTF-to-Arrow iteration for the MoQ trace Python package.

#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/babeltrace.rs"));
}
mod decode;
mod graph;

use arrow_array::RecordBatch;
use arrow_pyarrow::PyArrowType;
use arrow_schema::Schema;
use decode::Decoder;
use graph::{Graph, State};
use pyo3::{create_exception, exceptions::PyException, prelude::*};
use std::{collections::HashMap, sync::Arc};

create_exception!(_native_ctf, DecodeError, PyException);
type Schemas = Vec<(String, PyArrowType<Schema>)>;
type Batch = (String, PyArrowType<RecordBatch>);

fn decoder(schemas: Schemas, allowed: Option<Vec<u64>>, batch_size: usize) -> PyResult<Decoder> {
    let schemas = schemas
        .into_iter()
        .map(|(name, schema)| (name, Arc::new(schema.0)))
        .collect::<HashMap<_, _>>();
    Decoder::new(schemas, allowed, batch_size).map_err(DecodeError::new_err)
}

/// A file reader owns the graph before the callback state, so graph destruction
/// cannot access a state that has already been freed. Babeltrace is thread-bound.
#[pyclass(unsendable)]
struct Reader {
    graph: Option<Graph>,
    state: Box<State>,
    ended: bool,
}
#[pymethods]
impl Reader {
    #[new]
    fn new(
        paths: Vec<String>,
        schemas: Schemas,
        allowed: Option<Vec<u64>>,
        batch_size: usize,
    ) -> PyResult<Self> {
        let mut state = Box::new(State {
            decoder: decoder(schemas, allowed, batch_size)?,
            error: None,
        });
        let graph = Graph::new(paths, &mut state).map_err(DecodeError::new_err)?;
        Ok(Self {
            graph: Some(graph),
            state,
            ended: false,
        })
    }
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Batch>> {
        loop {
            if let Some(batch) = self.state.decoder.ready.pop_front() {
                return Ok(Some((batch.0, PyArrowType(batch.1))));
            }
            if self.ended {
                return Ok(None);
            }
            py.check_signals()?;
            match self.graph.as_mut().unwrap().step() {
                Ok(true) => {}
                Ok(false) => {
                    self.ended = true;
                    self.graph = None;
                    self.state.decoder.finish().map_err(DecodeError::new_err)?;
                }
                Err(error) => {
                    self.ended = true;
                    self.graph = None;
                    self.state.decoder.ready.clear();
                    return Err(DecodeError::new_err(
                        self.state.error.take().unwrap_or(error),
                    ));
                }
            }
        }
    }
}

/// The same decoder accepts real bt2 message wrappers for synthetic trace-IR
/// tests. A checked Python wrapper retains each message throughout its read.
#[pyclass(unsendable)]
struct MessageDecoder {
    decoder: Decoder,
}
#[pymethods]
impl MessageDecoder {
    #[new]
    fn new(schemas: Schemas, allowed: Option<Vec<u64>>, batch_size: usize) -> PyResult<Self> {
        Ok(Self {
            decoder: decoder(schemas, allowed, batch_size)?,
        })
    }
    fn push(&mut self, message: &Bound<'_, PyAny>) -> PyResult<Vec<Batch>> {
        let class = message
            .py()
            .import("bt2.message")?
            .getattr("_MessageConst")?;
        if !message.is_instance(&class)? {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "expected a Babeltrace message",
            ));
        }
        let address = message.getattr("addr")?.extract::<usize>()?;
        unsafe { self.decoder.push(address as *const ffi::bt_message) }
            .map_err(DecodeError::new_err)?;
        Ok(self
            .decoder
            .ready
            .drain(..)
            .map(|(name, batch)| (name, PyArrowType(batch)))
            .collect())
    }
    fn finish(&mut self) -> PyResult<Vec<Batch>> {
        self.decoder.finish().map_err(DecodeError::new_err)?;
        Ok(self
            .decoder
            .ready
            .drain(..)
            .map(|(name, batch)| (name, PyArrowType(batch)))
            .collect())
    }
}

#[pymodule]
fn _native_ctf(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<Reader>()?;
    module.add_class::<MessageDecoder>()?;
    module.add("DecodeError", module.py().get_type::<DecodeError>())?;
    Ok(())
}
