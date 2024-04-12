use either::Either;
use winnow::branch::alt;
use winnow::bytes::{tag, tag_no_case, take, none_of, take_until0, any, take_while0};
use winnow::character::{alpha0, alpha1, crlf, digit1, escaped_transform, space1};
use winnow::combinator::{cut_err, opt};
use winnow::error::{ErrorKind, VerboseError, ParseError};
use winnow::{IResult, Parser};
use winnow::multi::{length_data, many0};
use winnow::sequence::{delimited, preceded, separated_pair, terminated};
use winnow::stream::ContainsToken;

type Input<'i> = &'i str;
pub type ParseResult<'i, T> = IResult<Input<'i>, T, VerboseError<Input<'i>>>;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum OkNoBye {
    Ok,
    No,
    Bye,
}

impl std::fmt::Display for OkNoBye {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", match self {
            OkNoBye::Ok => "OK",
            OkNoBye::No => "NO",
            OkNoBye::Bye => "BYE",
        })
    }
}

pub type SieveUrl = String;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum QuotaVariant {
    None,
    MaxScripts,
    MaxSize,
}

type SieveString = String;
type HumanReadableString = SieveString;

#[derive(Debug, PartialEq, Clone)]
pub enum ResponseCode {
    AuthTooWeak,
    EncryptNeeded,
    Quota(QuotaVariant),
    Referral(SieveUrl),
    Sasl,
    TransitionNeeded,
    TryLater,
    Active,
    Nonexistent,
    AlreadyExists,
    Tag,
    Warnings,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Response {
    pub tag: OkNoBye,
    pub code: Option<(ResponseCode, Option<String>)>,
    pub human: Option<HumanReadableString>,
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct Version {
    major: u64,
    minor: u64,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Capability {
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


// see section 1.6 of rfc 5804
pub fn is_bad_sieve_name_char(c: char) -> bool {
    match c {
        c if (c <= 0x1f as char) => true,
        c if (c >= 0x7f as char && c <= 0x9f as char) => true,
        c if (c == '\u{2028}' || c == '\u{2029}') => true,
        _ => false,
    }
}

pub(crate) fn ok(input: Input) -> ParseResult<OkNoBye> {
    tag_no_case("OK").value(OkNoBye::Ok).parse_next(input)
}

pub(crate) fn no(input: Input) -> ParseResult<OkNoBye> {
    tag_no_case("NO").value(OkNoBye::No).parse_next(input)
}

pub(crate) fn bye(input: Input) -> ParseResult<OkNoBye> {
    tag_no_case("BYE").value(OkNoBye::Bye).parse_next(input)
}

pub(crate) fn nobye(input: Input) -> ParseResult<OkNoBye> {
    alt((no, bye))(input)
}

fn atom(input: Input) -> ParseResult<ResponseCode> {
    alt((
        tag_no_case("AUTH-TOO-WEAK").value(ResponseCode::AuthTooWeak),
        tag_no_case("ENCRYPT-NEEDED").value(ResponseCode::EncryptNeeded),
        tag_no_case("QUOTA/MAXSCRIPTS").value(ResponseCode::Quota(QuotaVariant::None)),
        tag_no_case("QUOTA/MAXSIZE").value(ResponseCode::Quota(QuotaVariant::MaxScripts)),
        tag_no_case("QUOTA").value(ResponseCode::Quota(QuotaVariant::MaxSize)),
        tag_no_case("REFERRAL").value(ResponseCode::Referral(SieveUrl::new())),
        tag_no_case("SASL").value(ResponseCode::Sasl),
        tag_no_case("TRANSITION-NEEDED").value(ResponseCode::TransitionNeeded),
        tag_no_case("TRYLATER").value(ResponseCode::TryLater),
        tag_no_case("ACTIVE").value(ResponseCode::Active),
        tag_no_case("NONEXISTENT").value(ResponseCode::Nonexistent),
        tag_no_case("ALREADYEXISTS").value(ResponseCode::AlreadyExists),
        tag_no_case("TAG").value(ResponseCode::Tag),
        tag_no_case("WARNINGS").value(ResponseCode::Warnings),
    )).parse_next(input)
}

#[test]
fn test_atom() {
    assert_eq!(atom.parse_next("SASL"), Ok(("", ResponseCode::Sasl)));
    assert!(atom.parse_next("ABCDE").is_err());
}

fn literal_s2c_len(input: Input) -> ParseResult<u64> {
    terminated(
        delimited(tag("{"), digit1.map_res(|s: &str| s.parse::<u64>()), tag("}")),
        crlf,
    )(input)
}

#[test]
fn test_literal_s2c_len() {
    assert!(matches!(literal_s2c_len("{3}\r\n"), Ok(("", 3))));
    assert!(matches!(literal_s2c_len("{0}\r\n"), Ok(("", 0))));
    assert!(matches!(literal_s2c_len("{3}"), Err(_)));
    assert!(matches!(literal_s2c_len("{3}\r\nab"), Ok(("ab", 3))));
}

// Needs to return String because quoted_string does too.
fn literal_s2c(input: Input) -> ParseResult<String> {
    length_data(literal_s2c_len).map(|s| s.to_owned()).parse_next(input)
}

#[test]
fn test_literal_s2c() {
    assert_eq!(literal_s2c("{3}\r\nabc").unwrap().1, "abc");
    assert!(literal_s2c("{4}\r\nabc").is_err());
    assert!(literal_s2c("{0}\r\n").is_ok());
}

fn sievestring_s2c(input: Input) -> ParseResult<String> {
    alt((literal_s2c, quoted_string))(input)
}

#[test]
fn test_sievestring_s2c() {
    assert_eq!(sievestring_s2c("{3}\r\nabc").unwrap().1, "abc");
    assert_eq!(sievestring_s2c("\"hello\"").unwrap().1, "hello");
}

fn literal_c2s_len(input: Input) -> ParseResult<u64> {
    terminated(
        delimited(
            tag("{"),
            digit1.map_res(|s: &str| s.parse::<u64>()),
            alt((tag("+}"), tag("}"))),
        ),
        crlf,
    )(input)
}

#[test]
fn test_literal_c2s_len() {
    test_literal_s2c_len();
    assert!(matches!(literal_c2s_len("{3+}\r\n"), Ok(("", 3))));
}

fn literal_c2s(input: Input) -> ParseResult<String> {
    length_data(literal_c2s_len).map(ToOwned::to_owned).parse_next(input)
}

#[test]
fn test_literal_c2s() {
    test_literal_s2c();
    assert_eq!(literal_c2s("{3+}\r\nabc").unwrap().1, "abc");
    assert!(literal_c2s("{4+}\r\nabc").is_err());
}

fn sievestring_c2s(input: Input) -> ParseResult<String> {
    alt((literal_c2s, quoted_string))(input)
}

#[test]
fn test_sievestring_c2s() {
    assert_eq!(sievestring_c2s("{3+}\r\nabc").unwrap().1, "abc");
    assert_eq!(sievestring_c2s("\"hello\"").unwrap().1, "hello");
}

fn code(input: Input) -> ParseResult<(ResponseCode, Option<String>)> {
    delimited(tag("("), (atom, opt(preceded(space1, sievestring_s2c))), tag(")"))(input)
}

#[test]
fn test_code() {
    assert!(matches!(
        code("(QUOTA)"),
        Ok(("", (ResponseCode::Quota(QuotaVariant::None), None)))
    ));
    assert_eq!(
        code("(TAG {16}\r\nSTARTTLS-SYNC-42)").unwrap(),
        ("", (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string())))
    );
    assert_eq!(
        code("(TAG \"STARTTLS-SYNC-42\")").unwrap(),
        ("", (ResponseCode::Tag, Some("STARTTLS-SYNC-42".to_string())))
    );
}


fn t() -> impl ContainsToken<char> {
    todo!()
}

fn quoted_string(input: Input) -> ParseResult<String> {
    delimited(
        tag("\""),
        escaped_transform(
            // TODO
            alpha0,
            '\\',
            alt((
                tag("\\").value("\\"),
                tag("\"").value("\""),
            ))
        ),
        tag("\"")
    )(input)
}

#[test]
fn test_quoted_string() {
    quoted_string("\"hello\"").unwrap();
    quoted_string("\"\"").unwrap();
    assert!(quoted_string("hello").is_err());
}

pub fn sieve_name_c2s(input: Input) -> ParseResult<String> {
    match sievestring_c2s(input) {
        Err(e) => Err(e),
        Ok((rest, s)) => match s.chars().find(|c| is_bad_sieve_name_char(*c)) {
            Some(_) => Err(winnow::error::ErrMode::Cut(ParseError::from_error_kind(input, ErrorKind::Char))),
            None => Ok((rest, s)),
        },
    }
}

#[test]
fn test_sieve_name_c2s() {
    sieve_name_c2s("\"hello\"").unwrap();
    sieve_name_c2s("\"hello\u{1337}\"").unwrap();
    sieve_name_c2s("{3}\r\nabc").unwrap();
    assert!(matches!(sieve_name_c2s("\"he\x1f\""), Err(winnow::error::ErrMode::Cut(_))));
    assert!(matches!(sieve_name_c2s("\"he\" \x1f"), Ok((" \x1f", _))));
}

pub fn active_sieve_name(input: Input) -> ParseResult<Option<String>> {
    opt(sieve_name_c2s)(input)
}

#[test]
fn test_active_sieve_name() {
    assert!(active_sieve_name("hello  ").unwrap().1.is_none());
    assert!(active_sieve_name("\"hello \" ").unwrap().1.is_some());
    assert!(active_sieve_name("\"hello\x7f \" ").is_err());
    assert!(active_sieve_name("\"\"").is_ok());
    assert!(matches!(active_sieve_name("hello   "), Ok(("hello   ", None))));
    assert!(matches!(active_sieve_name("   "), Ok((_, None))));
}

pub fn response_ok(input: Input) -> ParseResult<Response> {
    terminated(
        (ok, opt(preceded(space1, code)), opt(preceded(space1, quoted_string))).map(
            |(_, code, human)| Response {
                tag: OkNoBye::Ok,
                code,
                human,
            },
        ),
        crlf,
    )(input)
}

pub fn response_nobye(input: Input) -> ParseResult<Response> {
    terminated(
        ((nobye, opt(preceded(space1, code)), opt(preceded(space1, quoted_string)))).map(
            |(oknobye, code, human)| Response {
                tag: oknobye,
                code,
                human,
            },
        ),
        crlf,
    )(input)
}

pub fn response_oknobye(input: Input) -> ParseResult<Response> {
    alt((response_ok, response_nobye))(input)
}

#[test]
fn test_response() {
    response_oknobye("ok\r\n").unwrap();
    response_oknobye("nO\r\n").unwrap();
    response_oknobye("BYE\r\n").unwrap();
    response_oknobye("ok (QUOTA)\r\n").unwrap();
    response_oknobye("ok (QUOTA) \"hello\"\r\n").unwrap();
    assert!(matches!(response_oknobye("ok"), Err(_)));
    assert!(matches!(response_oknobye(" ok\r\n"), Err(_)));
    assert!(matches!(response_oknobye("ok (\r\n"), Err(_)));
    assert!(matches!(response_oknobye("ok (QUOTA\r\n"), Err(_)));
    assert!(matches!(response_oknobye("ok (QUOTA/)\r\n"), Err(_)));
}

pub fn response_getscript(input: Input) -> ParseResult<(Option<String>, Response)> {
    alt((
        separated_pair(sievestring_s2c, crlf, response_ok).map(|(s, r)| (Some(s), r)),
        response_nobye.map(|r| (None, r)),
    ))(input)
}

#[test]
fn test_response_getscript() {
    response_getscript("\"hello\"\r\nOK\r\n").unwrap();
    response_getscript("NO\r\n").unwrap();
    assert!(matches!(response_getscript("\"hello\"\r\nBYE\r\n"), Err(_)));
}

pub fn response_listscripts(input: Input) -> ParseResult<(Vec<(String, bool)>, Response)> {
    (
        many0(terminated(
            (sievestring_s2c, opt((space1, tag_no_case("ACTIVE"))).map(|o| o.is_some())),
            crlf,
        )),
        response_oknobye,
    ).parse_next(input)
}

#[test]
fn test_response_listscripts() {
    response_listscripts("\"script1\"\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("\"script1\" ACTIVE\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("\"script1\" active\r\n\"script2\"\r\nOK\r\n").unwrap();
    response_listscripts("OK\r\n").unwrap();
    response_listscripts("BYE\r\n").unwrap();
}

fn space_separated_string_s2c(input: Input) -> ParseResult<Vec<String>> {
    sievestring_s2c.map(|s| {
        if s.is_empty() {
            vec![]
        } else {
            s.split(' ').map(String::from).collect()
        }
    }).parse_next(input)
}

fn space_separated_string_not_empty_s2c(input: Input) -> ParseResult<Vec<String>> {
    sievestring_s2c.map_res(|s| {
        if s.is_empty() {
            Err("expected non-empty space-separated string, found empty string")
        } else {
            Ok(s.split(' ').map(String::from).collect())
        }
    }).parse_next(input)
}

fn number_string_s2c(input: Input) -> ParseResult<u64> {
    sievestring_s2c.map_res(|s| s.parse::<u64>()).parse_next(input)
}

fn version(input: Input) -> ParseResult<Version> {
    delimited(
        tag("\""),

            separated_pair(
                digit1.map_res(|s: &str| s.parse::<u64>()),
                tag("."),
                digit1.map_res(|s: &str| s.parse::<u64>()),
            ).map(
            |(major, minor)| Version { major, minor },
        ),
        tag("\""),
    )(input)
}

fn single_capability(input: Input) -> ParseResult<Capability> {
    //TODO capability name as accept literal-s2c
    terminated(
        alt((
            preceded(tag_no_case("\"IMPLEMENTATION\""), cut_err(preceded(space1, sievestring_s2c)))
                .map(Capability::Implementation),
            preceded(
                tag_no_case("\"SASL\""),
                cut_err(preceded(space1, space_separated_string_s2c)),
            )
                .map(Capability::Sasl),
            
            preceded(
                tag_no_case("\"SIEVE\""),
                cut_err(preceded(space1, space_separated_string_s2c)),
            ).map(Capability::Sieve),
            preceded(
                tag_no_case("\"MAXREDIRECTS\""),
                cut_err(preceded(space1, number_string_s2c))
            ).map(Capability::MaxRedirects),
            preceded(
                tag_no_case("\"NOTIFY\""),
                cut_err(preceded(space1, space_separated_string_not_empty_s2c)),
            ).map(Capability::Notify),
            tag_no_case("\"STARTTLS\"").value(Capability::StartTls),
            preceded(
                tag_no_case("\"LANGUAGE\""),
                cut_err(preceded(space1, sievestring_s2c))
            ).map(Capability::Language),
            preceded(tag_no_case("\"VERSION\""), cut_err(preceded(space1, version))).map(Capability::Version),
            preceded(tag_no_case("\"OWNER\""), cut_err(preceded(space1, sievestring_s2c))).map(Capability::Owner, ),
            (sievestring_s2c, opt(preceded(space1, sievestring_s2c))).map( |(cap, arg)| {
                Capability::Unknown(cap, arg)
            }),
        )),
        crlf,
    )(input)
}

#[test]
fn test_single_capability() {
    single_capability("\"CAPABILITY1\"\r\n").unwrap();
    single_capability("\"CAPABILITY2\" \"a b c d e\"\r\n").unwrap();
    assert!(single_capability("\"CAPABILITY2\" \r\n").is_err());
}

pub fn response_capabilities(input: Input) -> ParseResult<(Vec<Capability>, Response)> {
    (many0(single_capability), response_oknobye).parse_next(input)
}

#[test]
fn test_response_capabilities() {
    // let input = include_str!("test_input/response_capability-1.txt");
    // let error = response_capabilities(input).finish().err().unwrap();
    // eprintln!("{}", error);
    // assert_eq!(
    //     response_capabilities(input),
    //     Ok((
    //         "",
    //         (
    //             vec![
    //                 Capability::Implementation("Dovecot Pigeonhole".into()),
    //                 Capability::Sieve(vec![
    //                     "fileinto".into(),
    //                     "reject".into(),
    //                     "envelope".into(),
    //                     "encoded-character".into(),
    //                     "vacation".into(),
    //                     "subaddress".into(),
    //                     "comparator-i;ascii-numeric".into(),
    //                     "relational".into(),
    //                     "regex".into(),
    //                     "imap4flags".into(),
    //                     "copy".into(),
    //                     "include".into(),
    //                     "variables".into(),
    //                     "body".into(),
    //                     "enotify".into(),
    //                     "environment".into(),
    //                     "mailbox".into(),
    //                     "date".into(),
    //                 ]),
    //                 Capability::Notify(vec!["mailto".into()]),
    //                 Capability::Sasl(vec![]),
    //                 Capability::MaxRedirects(42),
    //                 Capability::StartTls,
    //                 Capability::Version(Version { major: 1, minor: 0 }),
    //             ],
    //             Response {
    //                 tag: OkNoBye::Ok,
    //                 code: None,
    //                 human: Some("Dovecot ready.".into()),
    //             }
    //         )
    //     ))
    // );
}

pub fn response_starttls(input: Input) -> ParseResult<(Vec<Capability>, Response)> {
    alt((
        preceded(response_ok, response_capabilities),
        response_nobye.map(|r| (Vec::new(), r)),
    ))(input)
}

#[test]
fn test_response_starttls() {
    response_starttls("OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
    response_starttls("BYE\r\n").unwrap();
}

/// Server responds to authenticate with either a challenge or a oknobye
/// response.
pub fn response_authenticate_initial(input: Input) -> ParseResult<Either<String, Response>> {
    alt((
        terminated(sievestring_s2c, crlf).map(|s| Either::Left(s)),
        response_nobye.map(|r| Either::Right(r)),
    ))(input)
}

#[test]
fn test_response_authenticate_initial() {
    response_authenticate_initial("{4}\r\nabcd\r\n").unwrap();
    response_authenticate_initial("BYE\r\n").unwrap();
}

/// Server responds to client response with oknobye and can also include new
/// capabilities if OK.
pub fn response_authenticate_complete(
    input: Input,
) -> ParseResult<(Option<Vec<Capability>>, Response)> {
    alt((
        (response_ok, opt(response_capabilities)).map(|(a, b)| match b {
            None => (None, a),
            Some((s, r)) => (Some(s), r),
        }),
        response_nobye.map(|r| (None, r)),
    ))(input)
}

#[test]
fn test_response_authenticate_complete() {
    response_authenticate_complete("OK\r\n\"CAPABILITY1\"\r\n\"CAPABILITY2\"\r\nOK\r\n").unwrap();
    response_authenticate_complete("BYE\r\n").unwrap();
}
