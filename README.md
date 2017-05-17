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
