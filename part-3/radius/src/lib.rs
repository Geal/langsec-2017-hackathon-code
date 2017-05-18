#[macro_use] extern crate nom;


#[cfg(test)]
mod tests {
    use nom::HexDisplay;
    const access_request   : &[u8] = include_bytes!("../../assets/radius-access-request.bin");
    const access_challenge : &[u8] = include_bytes!("../../assets/radius-access-challenge.bin");
    const access_reject    : &[u8] = include_bytes!("../../assets/radius-access-reject.bin");
    const access_accept    : &[u8] = include_bytes!("../../assets/radius-access-accept.bin");

    #[test]
    fn print() {
        println!("hexdump:\n{}", access_request.to_hex(16));
        //panic!();
    }

    #[test]
    fn it_works() {
    }
}
