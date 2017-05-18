# LangSec Workshop at IEEE Security & Privacy - Hackathon

Throughout this exercise, we will guide you in developing a nom parser for the RADIUS protocol.

The different steps of the exercise are in separate folders, named "part-0", "part-1", etc.

## The RADIUS protocol

RADIUS means "Remote Authentication Dial In User Service", it is defined in the
[RFC 2865](https://tools.ietf.org/html/rfc2865). This is a binary network format,
with the following layout:

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Authenticator                         |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      The Code field is one octet, and identifies the type of RADIUS
      packet.  When a packet is received with an invalid Code field, it
      is silently discarded.

      RADIUS Codes (decimal) are assigned as follows:

        1       Access-Request
        2       Access-Accept
        3       Access-Reject
        4       Accounting-Request
        5       Accounting-Response
       11       Access-Challenge
       12       Status-Server (experimental)
       13       Status-Client (experimental)
      255       Reserved

```

## Part 0 - prerequisites

## Installing Rust

First, you need to install Rust on your machine. The most common way is through
[Rustup](https://www.rustup.rs/), a tool used to manage different versions of Rust.
Yopu can install it directly like this:

```
curl https://sh.rustup.rs -sSf | sh
```

## Creating a project

Rust uses the `cargo` package manager to create projects, handle dependencies and
manage project builds. To create your first project, run the following command:

```
cargo new radius
```

The project has the following layout:

```
radius/
├── Cargo.toml
└── src
    └── lib.rs
```

The `Cargo.toml` file holds project metadata and dependencies. All of the code for
our library will be stored in the `src` folder.

## Importing dependencies

We will import [nom](https://github.com/geal/nom), the parser combinators library,
into our Rust project, by editing the `Cargo.toml` file:

```toml
[package]
name = "radius"
version = "0.1.0"
authors = ["it's you!"]

[dependencies]
nom = "^3.0"
```

Dependencies in Rust are usually defined by a version (with [semantic versioning](http://semver.org/)
for version constraints), to download them from [crates.io](https://crates.io), the package
repository for Rust. You can also [import other projects by path for URL to a git
repository](http://doc.crates.io/specifying-dependencies.html). Rust packages are
named "crates".

To actually use the dependency in our code, we must import the new library in `src/lib.rs`:

```rust
#[macro_use] extern crate nom;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}

```

We use `extern crate` for most import. For nom, we use the `macro_use` attribute to also import
its macros.

Now, we can build and the project:

```
$ cargo test
    Updating registry `https://github.com/rust-lang/crates.io-index`
   Compiling nom v3.0.0
   Compiling radius v0.1.0 (file:///Users/geal/presentations/langsec-2017-hackathon-code/radius)
warning: unused `#[macro_use]` import
 --> src/lib.rs:1:1
  |
1 | #[macro_use] extern crate nom;
  | ^^^^^^^^^^^^
  |
  = note: #[warn(unused_imports)] on by default

warning: unused `#[macro_use]` import
 --> src/lib.rs:1:1
  |
1 | #[macro_use] extern crate nom;
  | ^^^^^^^^^^^^
  |
  = note: #[warn(unused_imports)] on by default

    Finished dev [unoptimized + debuginfo] target(s) in 3.81 secs
     Running target/debug/deps/radius-762b6b3206085f4b

running 1 test
test tests::it_works ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured

   Doc-tests radius

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured
```

Rust includes a facility for unit testing with cargo and rustc, its compiler.
You'll see the `target/` folder just appeared: it will hold all the temporary
files for compilation, and the output files.

The `Cargo.lock` file was also created. It holds a list of the dependencies
downloaded. It is not very useful for libraries, but for executables, you would
usually commit this file, to fix the exact set of dependencies to use when
building the project (you can update the dependencies list with `cargo update`).

## Part 1: information gathering

To write a new parser, we need mainly three things:

- [specifications](https://tools.ietf.org/html/rfc2865)
- samples. For a network protocol, we can get some from [the WireShark wiki](https://wiki.wireshark.org/SampleCaptures)
- a way to compare our implementation with other ones. In our case, we can compare to the output of WireShark.
you can download Wireshark [here](https://www.wireshark.org/)

Since the data we want to parse is embeded in UCP packets inside a PCAP file,
we need to extract the raw bytes of the RADIUS protocol (unless you want to
also make a PCAP, IP and UDP parsers as well).

Select a packet, and in the lower window, right click on "Radius Protocol" and
choose "Export Packet Bytes":

![export packet data from Wireshark](assets/wireshark-export-bytes.png)

the `assets/` folder at the root of the project already contains some PCAP
traces and a few extracted RADIUS frames, so you can skip to Part 2.

## Part 2: start implementing the parser

Open the `assets/radius_localhost.pcapng` file and select the first packet. The raw data
corresponding to this packet is in `assets/radius-access-request.bin` (each raw data file
corresponds to the first appearance of that RADIUS packet type in the trace).

To begin parsing, we need to load the data in a buffer and observe it. Tahnkfully, Rust
provides a nice feature called `include_bytes`. This macro will, at compile time, embed
the content of a file as a byte array in your code. In `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    const access_request   : &[u8] = include_bytes!("../../assets/radius-access-request.bin");
    const access_challenge : &[u8] = include_bytes!("../../assets/radius-access-challenge.bin");
    const access_reject    : &[u8] = include_bytes!("../../assets/radius-access-reject.bin");
    const access_accept    : &[u8] = include_bytes!("../../assets/radius-access-accept.bin");
```

Each of the `access_*` variables is a "byte slice", as indicated by the type `&[u8]`. This
data type is fundamental in the way nom is built. It contains a pointer to the start of the
data, and a length. nom will move from slices like this from one parser to the next, avoiding
data copies in the process.

We can now access those slices and observe their content. A great way to explore a byte slice
is to reuse nom's hex viewer:

```rust
    // import the HexDisplay trait to activate the feature on slices
    use nom::HexDisplay;

    [...]

    #[test]
    fn print() {
        println!("hexdump:\n{}", access_request.to_hex(16));
        // adding a panic here to fail the test, otherwise the println output would be silent
        panic!();
    }
```

If you try to test the code, it should give you the following output:

```
$ cargo test
    Finished dev [unoptimized + debuginfo] target(s) in 0.0 secs
     Running target/debug/deps/radius-762b6b3206085f4b

running 2 tests
test tests::it_works ... ok
test tests::print ... FAILED

failures:

---- tests::print stdout ----
        hexdump:
00000000        01 67 00 57 40 b6 64 db f5 d6 81 b2 ad bd 17 69         .g.W@�d��ց���.i
00000010        51 51 18 c8 01 07 73 74 65 76 65 02 12 db c6 c4         QQ.�..steve..���
00000020        b7 58 be 14 f0 05 b3 87 7c 9e 2f b6 01 04 06 c0         �X�.�.��|�/�...�
00000030        a8 00 1c 05 06 00 00 00 7b 50 12 5f 0f 86 47 e8         �.......{P._.�G�
00000040        c8 9b d8 81 36 42 68 fc d0 45 32 4f 0c 02 66 00         ț؁6Bh��E2O..f.
00000050        0a 01 73 74 65 76 65                                    ..steve

thread 'tests::print' panicked at 'explicit panic', src/lib.rs:15
note: Run with `RUST_BACKTRACE=1` for a backtrace.


failures:
    tests::print

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured

error: test failed, to rerun pass '--lib'
```

The hexadecimal viewer is useful to verify what nom returned is what you expected.

### Let's write the first parser
