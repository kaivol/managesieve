#![feature(hash_raw_entry)]

mod client;
pub mod commands;
mod internal;

pub use client::{Connection, SieveError, RecoverableError};

#[macro_export]
macro_rules! bail {
    ($err:expr) => {
        return Err(core::convert::From::from($err))
    };
}