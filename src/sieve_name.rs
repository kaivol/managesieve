use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str;
use std::str::FromStr;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Default)]
#[repr(transparent)]
pub struct SieveNameString(String);

impl SieveNameString {
    pub fn new(name: impl Into<String>) -> Result<Self, SieveNameError> {
        let name = name.into();

        SieveNameStr::new(&name)?;
        Ok(SieveNameString(name))
    }

    pub fn as_sieve_name_str(&self) -> &SieveNameStr {
        unsafe { &*(self.0.as_str() as *const str as *const SieveNameStr) }
    }
}

impl Display for SieveNameString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for SieveNameString {
    type Target = SieveNameStr;

    fn deref(&self) -> &Self::Target {
        self.as_sieve_name_str()
    }
}

impl AsRef<str> for SieveNameString {
    fn as_ref(&self) -> &str {
        self.deref().as_ref()
    }
}

impl AsRef<SieveNameStr> for SieveNameString {
    fn as_ref(&self) -> &SieveNameStr {
        self.deref()
    }
}

impl FromStr for SieveNameString {
    type Err = SieveNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SieveNameString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SieveNameString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Debug)]
#[repr(transparent)]
pub struct SieveNameStr(str);

impl SieveNameStr {
    pub fn new(name: &impl AsRef<str>) -> Result<&Self, SieveNameError> {
        let name = name.as_ref();
        if is_bad_sieve_name(name) {
            Err(SieveNameError)
        } else {
            Ok(unsafe { &*(name as *const str as *const SieveNameStr) })
        }
    }
}

impl Display for SieveNameStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for SieveNameStr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
#[error("the given sieve script name is illegal")]
pub struct SieveNameError;

fn is_bad_sieve_name(name: &str) -> bool {
    name.chars().any(is_bad_sieve_name_char)
}

// see section 1.6 of rfc 5804
fn is_bad_sieve_name_char(c: char) -> bool {
    match c {
        c if c <= 0x1f as char => true,
        c if c >= 0x7f as char && c <= 0x9f as char => true,
        c if c == '\u{2028}' || c == '\u{2029}' => true,
        _ => false,
    }
}
