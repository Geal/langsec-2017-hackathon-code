#[macro_use] extern crate nom;

use nom::{be_u8, be_u16, IResult};

#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum RadiusCode {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13,
    Reserved = 255,
}

#[derive(Debug,PartialEq)]
pub struct RadiusData<'a> {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: &'a [u8], // 16 bytes
    pub attributes: Option<Vec<RadiusAttribute<'a>>>,
}

#[derive(Debug,PartialEq)]
pub struct RadiusAttribute<'a> {
    pub typ: u8,
    pub len: u8,
    pub val: &'a [u8],
}

pub fn parse_radius_data(i:&[u8]) -> IResult<&[u8],RadiusData> {
    do_parse!(i,
        c:    be_u8 >>
        id:   be_u8 >>
        len:  be_u16 >>
        auth: take!(16) >>
        attr: cond!(len > 20,
                    flat_map!(take!(len - 20),complete!(many1!(parse_radius_attribute)))
        ) >>
        (
            RadiusData {
                code: c,
                identifier: id,
                length: len,
                authenticator: auth,
                attributes: attr,
            }
        )
    )
}

pub fn parse_radius_attribute(i:&[u8]) -> IResult<&[u8],RadiusAttribute> {
    do_parse!(i,
        t: be_u8 >>
        l: verify!(be_u8, |val| val >= 2) >>
        v: take!(l-2) >>
        (
            RadiusAttribute {
                typ: t,
                len: l,
                val: v,
            }
        )
    )
}

#[cfg(test)]
mod tests {
    use nom::{HexDisplay,IResult};
    use super::{parse_radius_data,RadiusData,RadiusAttribute};

    const access_request   : &[u8] = include_bytes!("../../../assets/radius-access-request.bin");
    const access_challenge : &[u8] = include_bytes!("../../../assets/radius-access-challenge.bin");
    const access_reject    : &[u8] = include_bytes!("../../../assets/radius-access-reject.bin");
    const access_accept    : &[u8] = include_bytes!("../../../assets/radius-access-accept.bin");
    const fuzzer_sample    : &[u8] = include_bytes!("../fuzz/artifacts/fuzzer_script_1/crash-d575696eb7fb470793d82e5b8f2e3a867baf8c0d");

    #[test]
    fn basic_radius_data() {
        println!("hexdump:\n{}", access_request.to_hex(16));

        assert_eq!(
            parse_radius_data(access_request),
            IResult::Done(
                &access_request[access_request.len()..],
                RadiusData {
                    code: 1,
                    identifier: 103,
                    length: 87,
                    authenticator: &access_request[4..20],
                    attributes:    Some(vec!(
                        RadiusAttribute {
                            typ: 1,
                            len: 7,
                            val: &access_request[22..27],
                        },
                        RadiusAttribute {
                            typ: 2,
                            len: 18,
                            val: &access_request[29..45],
                        },
                        RadiusAttribute {
                            typ: 4,
                            len: 6,
                            val: &access_request[47..51],
                        },
                        RadiusAttribute {
                            typ: 5,
                            len: 6,
                            val: &access_request[53..57],
                        },
                        RadiusAttribute {
                            typ: 80,
                            len: 18,
                            val: &access_request[59..75],
                        },
                        RadiusAttribute {
                            typ: 79,
                            len: 12,
                            val: &access_request[77..87],
                        },
                    )),
                }
            )
        );
    }


    #[test]
    fn fuzzer_test() {
        let res = parse_radius_data(fuzzer_sample);
        println!("res: {:?}", res);
        panic!();
    }
}
