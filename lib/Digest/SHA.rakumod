#!/usr/bin/env raku
unit module Digest::SHA;

=begin Credits
The code for SHA-1 comes from Rosetta code:

L<http://rosettacode.org/wiki/SHA-1#Perl_6>

The code for SHA-256 comes from a javascript implementation:

Crypto-JS v2.0.0
http:#code.google.com/p/crypto-js/
Copyright (c) 2009, Jeff Mott. All rights reserved.
http:#code.google.com/p/crypto-js/wiki/License

It was heavily modified, though.
=end Credits

proto sha1($)   returns blob8 is export {*}
proto sha256($) returns blob8 is export {*}
proto sha512($) returns blob8 is export {*}

proto hmac(|) returns blob8 is export {*}

proto hmac-sha1  ($, $) returns blob8 is export {*}
proto hmac-sha256($, $) returns blob8 is export {*}
proto hmac-sha512($, $) returns blob8 is export {*}

multi sha1  (Str $str) { samewith $str.encode }
multi sha256(Str $str) { samewith $str.encode }
multi sha512(Str $str) { samewith $str.encode }

multi hmac-sha1  (Str   $a,       $b) { samewith $a.encode, $b }
multi hmac-sha1  (blob8 $a, Str   $b) { samewith $a, $b.encode }
multi hmac-sha256(Str   $a,       $b) { samewith $a.encode, $b }
multi hmac-sha256(blob8 $a, Str   $b) { samewith $a, $b.encode }
multi hmac-sha512(Str   $a,       $b) { samewith $a.encode, $b }
multi hmac-sha512(blob8 $a, Str   $b) { samewith $a, $b.encode }

constant @primes = grep *.is-prime, 2 .. *;

my \f = { ($^a +& $^b) +| (+^$^a +& $^c) },
        { $^a +^ $^b +^ $^c },
        { ($^a +& $^b) +| ($^a +& $^c) +| ($^b +& $^c) },
        { $^a +^ $^b +^ $^c };
 
sub sha1-pad(blob8 $msg --> blob32) {
  my $bits = 8 * $msg;
  blob32.new:
    flat (flat @$msg, 0x80, 0x00 xx (-($bits div 8 + 1 + 8) % 64))
    .rotor(4).map({ :256[|@^a] }), ($bits +> 32, $bits) »%» 2**32;
}
 
sub sha1-block(buf32 $H is rw, @M) {
  constant @K = 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6;
  sub S($n, $x) { ($x +< $n) +| ($x +> (32-$n)) }
  my uint32 @W = @M;
  @W.push: S(1, @W[$_-3] +^ @W[$_-8] +^ @W[$_-14] +^ @W[$_-16]) for 16..79;

  my buf32 $h = $H.clone;
  $h[] = [
    S(5,$h[0]) + f[$_ div 20]($h[1],$h[2],$h[3]) + $h[4] + @W[$_] + @K[$_ div 20],
    $h[0],
    S(30,$h[1]),
    $h[2],
    $h[3]
  ] for ^80;
    $H[] Z[+=] $h[];
}
 
multi sha1(blob8 $msg) {
  my blob32 $M = sha1-pad($msg);
  my buf32 $H .= new: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0;
  sha1-block($H, $M.subbuf: $_, 16) for 0, 16 ...^ +$M;
  blob8.new: $H.map: |*.polymod(256 xx 3).reverse
}

sub rotr(uint32 $n, uint32 $b) { $n +> $b +| $n +< (32 - $b) }
 
multi sha256(blob8 $data) {
  sub init(&f) { map { (($_ - .Int)*2**32).Int }, map &f, @primes }
  state blob32 $K .= new: init(* **(1/3))[^64];
  my $l = 8 * my buf8 $buf .= new: $data;
  # The message is padded with a single 1 bit, and then zero bits until the
  # length (in bits) is 448 mod 512.
  push $buf, 0x80;
  push $buf, 0 until (8*$buf - 448) %% 512;

  # The length of the message is pushed, with an eight bytes encoding
  push $buf, |$l.polymod(256 xx 7).reverse;

  # the message is turned into a list of four-bytes words
  my blob32 $words .= new: $buf.rotor(4).map: { :256[@$_] }

  my buf32 $H .= new: init(&sqrt)[^8];
  my buf32 $w .= new: 0 xx 64;

  loop (my int $i = 0; $i < +$words; $i += 16) {
    my buf32 $h = $H.clone;
    loop (my int $j = 0; $j < 64; $j += 1) {
      $w[$j] = $j < 16 ?? $words[$j + $i] // 0 !!
	(rotr($w[$j-15], 7) +^ rotr($w[$j-15], 18) +^ $w[$j-15] +> 3) +
	$w[$j-7] +
	(rotr($w[$j-2], 17) +^ rotr($w[$j-2], 19)  +^ $w[$j-2] +> 10) +
	$w[$j-16];
      my $ch = $h[4] +& $h[5] +^ +^$h[4] +& $h[6];
      my $maj = $h[0] +& $h[2] +^ $h[0] +& $h[1] +^ $h[1] +& $h[2];
      my $σ0 = rotr($h[0], 2) +^ rotr($h[0], 13) +^ rotr($h[0], 22);
      my $σ1 = rotr($h[4], 6) +^ rotr($h[4], 11) +^ rotr($h[4], 25);
      my $t1 = $h[7] + $σ1 + $ch + $K[$j] + $w[$j];
      my $t2 = $σ0 + $maj;
      $h[] = [
	$t1 + $t2, $h[0], $h[1], $h[2],
	$h[3] + $t1, $h[4], $h[5], $h[6]
      ];
    }
    $H[] Z[+=] $h[];
  }
  return blob8.new: $H.map: |*.polymod(256 xx 3).reverse;
}

multi sha512(blob8 $b) {
  given run <openssl dgst -sha512 -binary>, :in, :out, :bin {
    .in.write: $b;
    .in.close;
    return .out.slurp: :close;
  }
}

multi hmac-sha1(blob8 $a, blob8 $b) {
  my $hexkey = $b».fmt("%02x").join;
  given run |qqw{openssl mac -binary -digest SHA1 -macopt hexkey:$hexkey -in - HMAC},
    :in, :out, :bin {
    .in.write: $a;
    .in.close;
    return .out.slurp: :close;
  }
}

multi hmac-sha256(blob8 $a, blob8 $b) {
  my $hexkey = $b».fmt("%02x").join;
  given run |qqw{openssl mac -binary -digest SHA256 -macopt hexkey:$hexkey -in - HMAC},
    :in, :out, :bin {
    .in.write: $a;
    .in.close;
    return .out.slurp: :close;
  }
}

multi hmac-sha512(blob8 $a, blob8 $b) {
  given run |<openssl dgst -sha512 -mac hmac -binary -macopt>,
    "hexkey:{$b».fmt("%02x").join}", :in, :out, :bin {
    .in.write: $a;
    .in.close;
    return .out.slurp: :close;
  }
}

# vim: ft=raku
