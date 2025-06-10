use crate::{ResponseInfo, Version};

pub(crate) mod responses;

macro_rules! tag_variant {
    ($($name:ident),*) => {
        pub mod tag_trait {
            $(
                pub trait $name: std::fmt::Debug {}
            )*
        }
        pub mod tag {
            $(
                #[derive(Debug, PartialEq, Clone, Copy)]
                pub struct $name;
                impl super::tag_trait::$name for $name {}
                impl super::tag_trait::$name for std::convert::Infallible {}
            )*
        }
    };
}
tag_variant!(Ok, No, Bye);

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Tag<OK: tag_trait::Ok, NO: tag_trait::No, BYE: tag_trait::Bye> {
    Ok(OK),
    No(NO),
    Bye(BYE),
}

impl<OK: tag_trait::Ok, NO: tag_trait::No, BYE: tag_trait::Bye> Tag<OK, NO, BYE> {
    pub fn is_no(&self) -> bool {
        matches!(self, Tag::No(_))
    }
}

impl<NO: tag_trait::No, BYE: tag_trait::Bye> Tag<tag::Ok, NO, BYE> {
    fn ok() -> Self {
        Self::Ok(tag::Ok)
    }
}

impl<OK: tag_trait::Ok, BYE: tag_trait::Bye> Tag<OK, tag::No, BYE> {
    fn no() -> Self {
        Self::No(tag::No)
    }
}

impl<OK: tag_trait::Ok, NO: tag_trait::No> Tag<OK, NO, tag::Bye> {
    fn bye() -> Self {
        Self::Bye(tag::Bye)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Response<OK: tag_trait::Ok, NO: tag_trait::No, BYE: tag_trait::Bye> {
    pub tag: Tag<OK, NO, BYE>,
    pub info: ResponseInfo,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum Capability {
    Implementation(String),
    Sasl(Vec<String>),
    Sieve(Vec<String>),
    StartTls,
    MaxRedirects(u64),
    Notify(Vec<String>),
    Language(String),
    Owner(String),
    Version(Version),
    Unknown(String, Option<String>),
}
