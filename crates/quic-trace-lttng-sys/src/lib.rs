//! Raw bindings to the native `quic_trace` LTTng-UST provider.

#![cfg(target_os = "linux")]
#![allow(non_camel_case_types, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
