#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate radius;

use radius::parse_radius_data;

fuzz_target!(|data: &[u8]| {
    let result = parse_radius_data(data);
});
