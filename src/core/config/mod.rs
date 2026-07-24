//! Config: types + file-parser for routa's `key = value` / `[pool NAME]`
//! config-file syntax. See parser.rs's module doc for the full grammar

mod parse_helpers;
mod parser;
mod types;

pub use parse_helpers::{ConfigWarning, ParseContext};
pub use parser::{load, parse_file};
pub use types::*;
