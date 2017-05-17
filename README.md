# LangSec Workshop at IEEE Security & Privacy - Hackathon

Throughout this exercise, we will guide you in developing a nom parser for the RADIUS protocol.

The different steps of the exercise are in separate branches, named "part-0", "part-1", etc.
To jump directly to one of the steps, execute this command:

```
git checkout part-1
```

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


