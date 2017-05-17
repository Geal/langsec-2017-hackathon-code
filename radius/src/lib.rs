#[macro_use] extern crate nom;

#[cfg(test)]
mod tests {
    const access_request   : &[u8] = include_bytes!("../../assets/radius-access-request.bin");
    const access_challenge : &[u8] = include_bytes!("../../assets/radius-access-challenge.bin");
    const access_reject    : &[u8] = include_bytes!("../../assets/radius-access-reject.bin");
    const access_accept    : &[u8] = include_bytes!("../../assets/radius-access-accept.bin");

    #[test]
    fn it_works() {
    }
}
