[![SparrowCI](https://ci.sparrowhub.io/project/gh-grondilu-libdigest-raku/badge)](https://ci.sparrowhub.io)
# Digests in raku

This is a [raku](https://raku.org/) module implementing some digest algorithms
in pure raku (no parrot or nqp:: code).

## Synopsis

Nb.  Since commit 911c292688ad056a98285f7930297c5e1aea3bfb,
there is no `Digest` module anymore, the submodules, `Digest::MD5`, `Digest::SH1` and
so on must be used directly.
    
    use Digest::MD5;
    say md5      "hello";
    use Digest::HMAC;
    say hmac
      key => "key",
      msg => "The quick brown fox jumps over the lazy dog", 
      hash => &md5,
      block-size => 64;

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
  - hmac
* Digest::SHA1
  - sha1
* Digest::SHA2
  - sha224
  - sha256
  - sha384
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

