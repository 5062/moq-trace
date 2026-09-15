//! Raw bindings to the native `moq_trace` object event provider.

#![cfg(target_os = "linux")]
#![allow(non_camel_case_types, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
