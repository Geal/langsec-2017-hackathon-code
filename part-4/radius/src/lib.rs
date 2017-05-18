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
    pub attributes: Option<&'a[u8]>,
}

pub fn parse_radius_data(i:&[u8]) -> IResult<&[u8],RadiusData> {
    do_parse!(i,
        c:    be_u8 >>
        id:   be_u8 >>
        len:  be_u16 >>
        auth: take!(16) >>
        attr: cond!(len > 20, take!(len - 20)) >>
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

#[cfg(test)]
mod tests {
    use nom::{HexDisplay,IResult,Needed};
    use super::{parse_radius_data,RadiusData};

    const access_request   : &[u8] = include_bytes!("../../../assets/radius-access-request.bin");
    const access_challenge : &[u8] = include_bytes!("../../../assets/radius-access-challenge.bin");
    const access_reject    : &[u8] = include_bytes!("../../../assets/radius-access-reject.bin");
    const access_accept    : &[u8] = include_bytes!("../../../assets/radius-access-accept.bin");

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
                    attributes:    Some(&access_request[20..])
                }
            )
        );
    }

    #[test]
    fn print() {
        println!("hexdump:\n{}", access_request.to_hex(16));
        //panic!();
    }
}
