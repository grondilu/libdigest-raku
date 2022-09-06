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

multi sha1  (Str $str) { samewith $str.encode }
multi sha256(Str $str) { samewith $str.encode }
multi sha512(Str $str) { samewith $str.encode }

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
 
sub sha1-block(blob32 $H, blob32 $M --> blob32) {
  constant @K = 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6;
  sub S($n, $x) { ($x +< $n) +| ($x +> (32-$n)) }
  my uint32 @W = @$M;
  @W.push: S(1, @W[$_-3] +^ @W[$_-8] +^ @W[$_-14] +^ @W[$_-16]) for 16..79;
  blob32.new: $H Z+ (
    reduce -> blob32 $b, $i {
      blob32.new:
	S(5,$b[0]) + f[$i div 20]($b[1],$b[2],$b[3]) + $b[4] + @W[$i] + @K[$i div 20],
	$b[0],
	S(30,$b[1]),
	$b[2],
	$b[3]
    }, $H, |^80
  )
}
 
multi sha1(blob8 $msg) {
  blob8.new: (
    reduce &sha1-block,
    (constant $ = blob32.new: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
    |map { blob32.new: @$_ }, (sha1-pad $msg).rotor(16);
  ).map: |*.polymod(256 xx 3).reverse
}

 
multi sha256(blob8 $data) {

  sub rotr($n, $b) { $n +> $b +| $n +< (32 - $b) }
  sub init(&f) { map { (($_ - .Int)*2**32).Int }, map &f, @primes }
  sub  Ch { $^x +& $^y +^ +^$x +& $^z }
  sub Maj { $^x +& $^y +^ $x +& $^z +^ $y +& $z }
  sub Σ0 { rotr($^x,  2) +^ rotr($x, 13) +^ rotr($x, 22) }
  sub Σ1 { rotr($^x,  6) +^ rotr($x, 11) +^ rotr($x, 25) }
  sub σ0 { rotr($^x,  7) +^ rotr($x, 18) +^ $x +>  3 }
  sub σ1 { rotr($^x, 17) +^ rotr($x, 19) +^ $x +> 10 }

  my $l = 8 * my buf8 $buf .= new: $data;
  push $buf, 0x80;
  push $buf, 0 until (8*$buf - 448) %% 512;
  push $buf, |$l.polymod(256 xx 7).reverse;

  return blob8.new: 
    map |*.polymod(256 xx 3).reverse,
    |reduce -> $H, $block {
      my blob32 $w .= new: |@$block,
	{  my uint32 $ = σ0(@_[*-15]) + @_[*-7] + σ1(@_[*-2]) + @_[*-16] } ... {$++ == 64}

      blob32.new: $H[] Z+
	reduce -> blob32 $h, $j {
	  my uint32 ($T1, $T2) =
	    $h[7] + Σ1($h[4]) + Ch(|$h[4..6]) + (constant @ = init(* **(1/3))[^64])[$j] + $w[$j],
	    Σ0($h[0]) + Maj(|$h[0..2]);
	  blob32.new: $T1 + $T2, $h[0], $h[1], $h[2], $h[3] + $T1, $h[4], $h[5], $h[6];
	}, $H, |^64;
    },
    (constant $ = blob32.new: init(&sqrt)[^8]),
    |blob32.new($buf.rotor(4).map: { :256[@$_] }).rotor(16)
}

multi sha512(blob8 $data) {
 
  sub accurate-root ( UInt $p where * >= 2, UInt $n --> FatRat ) {
    my $N = $n*2**(64*$p);
    (exp((log($n) + 64*$p*log(2))/$p).Int, { ( ($p-1) * $^x + $N div $x**($p-1) ) div $p } ... *)
    .first({ $_**$p ≤ $N < ($_+1)**$p })
    .FatRat / 2**64
  }

  sub rotr($n, $b) { $n +> $b +| $n +< (64 - $b) }
  sub init(&f) { map { (($_ - .Int)*2**64).Int }, map &f, @primes }
  sub  Ch { $^x +& $^y +^ +^$x +& $^z }
  sub Maj { $^x +& $^y +^ $x +& $^z +^ $y +& $z }
  sub Σ0 { rotr($^x, 28) +^ rotr($x, 34) +^ rotr($x, 39) }
  sub Σ1 { rotr($^x, 14) +^ rotr($x, 18) +^ rotr($x, 41) }
  sub σ0 { rotr($^x,  1) +^ rotr($x,  8) +^ $x +> 7 }
  sub σ1 { rotr($^x, 19) +^ rotr($x, 61) +^ $x +> 6 }

  constant $K = blob64.new: init({ accurate-root(3, $_) })[^80];
  my buf64 $H .= new:
    constant $ = blob64.new: init({ accurate-root(2, $_)})[^8];
  my buf64 $w .= new: 0 xx 80;

  my $l = 8 * my buf8 $buf .= new: $data;
  push $buf, 0x80;
  push $buf, 0 until (8*$buf - 896) %% 1024;
  push $buf, |$l.polymod(256 xx 15).reverse;

  my blob64 $words .= new: $buf.rotor(8).map: { :256[@$_] }
  loop (my int $i = 0; $i < +$words; $i += 16) {
    my buf64 $h = $H.clone;
    for ^80 -> $t {
      $w[$t] = (
	$t < 16 ?? $words[$t + $i] // 0 !!
	σ0($w[$t-15]) + $w[$t-7] + σ1($w[$t-2]) + $w[$t-16];
      ) % 2**64;
      my uint64 ($T1, $T2) = map *%2**64,
	$h[7] + Σ1($h[4]) + Ch(|$h[4..6]) + $K[$t] + $w[$t],
	Σ0($h[0]) + Maj(|$h[0..2]);
	
      $h[] = [ map *%2**64, 
	$T1 + $T2, $h[0], $h[1], $h[2],
	$h[3] + $T1, $h[4], $h[5], $h[6]
      ];
    }
    $H[] = [map * % 2**64, ($H[] Z+ $h[])];
  }
  return blob8.new: $H.map: |*.polymod(256 xx 7).reverse;
}

# vim: ft=raku
