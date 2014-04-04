This is a perl6 module implementing some digest algorithms in pure Perl6 (no parrot or nqp:: code).

The interface is minimal: functions only return Blob and only take a Blob as
argument.  It's up to the user to turn it into an hex string if he needs to.

    use Digest::SHA;
    say my $sha256 = sha256 "hello".encode: 'ascii';
    
    use Digest::RIPEMD;
    say rmd160 "bye".encode: "ascii";

    sub buf_to_hex { [~] $^buf.list».fmt: "%02x" }
    say buf_to_hex $sha256;

Currently implemented:

* Digest
  - md5
* Digest::SHA :
  - sha256
  - sha1
* Digest::RIPEMD :
  - rmd160

This work is published under the terms of the artistic license, as rakudo is.
See LICENSE file.

