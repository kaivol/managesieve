use core::str;
use std::collections::hash_map::RawEntryMut;
use std::collections::HashMap;

use errors::CapabilitiesError;

use crate::client::Capabilities;
use crate::internal::command::IllegalScriptName;
use crate::internal::parser::{Capability, Version};

pub mod authenticate;
pub mod connect;
pub mod errors;
pub mod have_space;
pub mod list_scripts;
pub mod logout;
pub mod start_tls;

#[repr(transparent)]
pub struct ScriptName(str);

impl ScriptName {
    pub fn new(name: &str) -> Result<&Self, IllegalScriptName> {
        if name.chars().any(crate::internal::parser::is_bad_sieve_name_char) {
            return Err(IllegalScriptName);
        }
        Ok(unsafe { &*(name.as_bytes() as *const [u8] as *const ScriptName) })
    }
}

impl AsRef<str> for ScriptName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub(crate) fn verify_capabilities(
    capabilities: Vec<Capability>,
) -> Result<Capabilities, CapabilitiesError> {
    let mut implementation: Option<String> = None;
    let mut sasl: Option<Vec<String>> = None;
    let mut sieve: Option<Vec<String>> = None;
    let mut start_tls: Option<()> = None;
    let mut max_redirects: Option<u64> = None;
    let mut notify: Option<Vec<String>> = None;
    let mut language: Option<String> = None;
    let mut owner: Option<String> = None;
    let mut version: Option<Version> = None;

    let mut others: HashMap<String, Option<String>> = HashMap::new();

    fn try_set<T>(field: &mut Option<T>, value: T, name: &str) -> Result<(), CapabilitiesError> {
        if field.replace(value).is_some() {
            Err(CapabilitiesError::DuplicateCapability {
                capability: name.into(),
            })
        } else {
            Ok(())
        }
    }

    for capability in capabilities {
        match capability {
            Capability::Implementation(c) => try_set(&mut implementation, c, "IMPLEMENTATION")?,
            Capability::Sasl(c) => try_set(&mut sasl, c, "SASL")?,
            Capability::Sieve(c) => try_set(&mut sieve, c, "SIEVE")?,
            Capability::StartTls => try_set(&mut start_tls, (), "STARTTLS")?,
            Capability::MaxRedirects(c) => try_set(&mut max_redirects, c, "MAX_REDIRECTS")?,
            Capability::Notify(c) => try_set(&mut notify, c, "NOTIFY")?,
            Capability::Language(c) => try_set(&mut language, c, "LANGUAGE")?,
            Capability::Owner(c) => try_set(&mut owner, c, "OWNER")?,
            Capability::Version(c) => try_set(&mut version, c, "VERSION")?,
            Capability::Unknown(name, value) => {
                match others.raw_entry_mut().from_key(&name) {
                    RawEntryMut::Vacant(v) => {
                        v.insert(name, value);
                    }
                    RawEntryMut::Occupied(_) => {
                        return Err(CapabilitiesError::DuplicateCapability { capability: name });
                    }
                }
                // match others.entry(name) {
                //     Entry::Vacant(v) => {
                //         v.insert(value);
                //     }
                //     Entry::Occupied(o) => {
                //         return Err(CapabilitiesError::DuplicateCapability { capability: o.key().clone() });
                //     }
                // }
            }
        }
    }
    match (implementation, sieve, version) {
        (Some(implementation), Some(sieve), Some(version)) => Ok(Capabilities {
            implementation,
            sasl: sasl.unwrap_or_default(),
            sieve,
            start_tls: start_tls.is_some(),
            max_redirects,
            notify,
            language,
            owner,
            version,
            others,
        }),
        (None, _, _) => Err(CapabilitiesError::MissingImplementation),
        (_, None, _) => Err(CapabilitiesError::MissingSieve),
        (_, _, None) => Err(CapabilitiesError::MissingVersion),
    }
}
