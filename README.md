# Digests in pure raku

This is a perl6 module implementing some digest algorithms in pure Perl6 (no parrot or nqp:: code).

## Synopsis

    use Digest::SHA;
    say my $sha256 = sha256 "hello";
    say my $sha256 = sha256 "Привет".encode: 'utf8-c8';
    
    use Digest::RIPEMD;
    say rmd160 "bye";

## Features

Currently implemented:

* Digest
  - md5
* Digest::SHA :
  - sha256
  - sha1
* Digest::RIPEMD :
  - rmd160

## Disclaimer

PERFORMANCE WARNING: currently, execution is much slower than with most other programming languages.

## License

This work is published under the terms of the artistic license, as rakudo is.
See LICENSE file.

