# Digests in raku

This is a [raku](https://raku.org/) module implementing some digest algorithms
in pure raku (no parrot or nqp:: code).

The `Digest` module also exports a subroutine `blob-to-hex` to turn a blob into
a hexadecimal string representation.

## Synopsis
    
    use Digest;
    say md5      "hello";

    use Digest::SHA1;
    say sha1     "Hola";

    use Digest::SHA2;
    say sha256   "Привет"; 

    use Digest::SHA3;
    say sha3_256 "bonjour";
    
    use Digest::RIPEMD;
    say rmd160   "bye";

## Features

Currently implemented:

* Digest
  - md5
  - blob-to-hex
* Digest::SHA1
  - sha1
* Digest::SHA2
  - sha256
  - sha512
* Digest::SHA3
  - sha3\_224
  - sha3\_256
  - sha3\_384
  - sha3\_512
* Digest::RIPEMD :
  - rmd160

## Disclaimer

PERFORMANCE WARNING: currently, execution is much slower than with most other programming languages.

## License

This work is published under the terms of the artistic license, as rakudo is.
See LICENSE file.

