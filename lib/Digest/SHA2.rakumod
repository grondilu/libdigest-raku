#!/usr/bin/env raku
unit module Digest::SHA2;

constant @primes = grep *.is-prime, 2 .. *;

proto sha256($) returns blob8 is export {*}
proto sha512($) returns blob8 is export {*}

multi sha256(Str $str) { samewith $str.encode }
multi sha512(Str $str) { samewith $str.encode }

multi sha256(blob8 $data) {

  sub rotr(uint32 $n, UInt $b) { $n +> $b +| $n +< (32 - $b) }
  sub init { map { (($_ - .floor)*2**32).floor } o &^f, @primes }
  sub  Ch { $^x +& $^y +^ +^$x +& $^z }
  sub Maj { $^x +& $^y +^ $x +& $^z +^ $y +& $z }
  sub Σ0 { rotr($^x,  2) +^ rotr($x, 13) +^ rotr($x, 22) }
  sub Σ1 { rotr($^x,  6) +^ rotr($x, 11) +^ rotr($x, 25) }
  sub σ0 { rotr($^x,  7) +^ rotr($x, 18) +^ $x +>  3 }
  sub σ1 { rotr($^x, 17) +^ rotr($x, 19) +^ $x +> 10 }

  return blob8.new: 
    map |*.polymod(256 xx 3).reverse,
    |reduce -> $H, $block {
      blob32.new: $H[] Z+
	reduce -> blob32 $h, $j {
	  my uint32 ($T1, $T2) =
	    $h[7] + Σ1($h[4]) + Ch(|$h[4..6])
	    + (constant @ = init(* **(1/3))[^64])[$j]
	    + (
	      (state buf32 $w .= new)[$j] = $j < 16 ?? $block[$j] !!
	      σ0($w[$j-15]) + $w[$j-7] + σ1($w[$j-2]) + $w[$j-16]
	    ),
	    Σ0($h[0]) + Maj(|$h[0..2]);
	  blob32.new: $T1 + $T2, $h[0], $h[1], $h[2], $h[3] + $T1, $h[4], $h[5], $h[6];
	}, $H, |^64;
    },
    (constant $ = blob32.new: init(&sqrt)[^8]),
    |blob32.new(
      blob8.new(
	@$data,
	0x80,
	0 xx (-($data + 1 + 8) mod 64),
	(8*$data).polymod(256 xx 7).reverse
      ).rotor(4)
      .map: { :256[@$_] }
    ).rotor(16)
}

multi sha512(blob8 $data) {
 
  sub infix:<√>( UInt $p where * >= 2, UInt $n --> FatRat ) {
    my $N = $n*2**(64*$p);
    (exp(log($n)/$p + 64*log(2)).Int, { ( ($p-1) * $^x + $N div $x**($p-1) ) div $p } ... *)
    .first({ $_**$p ≤ $N < ($_+1)**$p })
    .FatRat / 2**64
  }

  sub rotr($n, $b) { $n +> $b +| $n +< (64 - $b) }
  sub init(&f) { map { (($_ - .floor)*2**64).floor } o &f, @primes }
  sub  Ch { $^x +& $^y +^ +^$x +& $^z }
  sub Maj { $^x +& $^y +^ $x +& $^z +^ $y +& $z }
  sub Σ0 { rotr($^x, 28) +^ rotr($x, 34) +^ rotr($x, 39) }
  sub Σ1 { rotr($^x, 14) +^ rotr($x, 18) +^ rotr($x, 41) }
  sub σ0 { rotr($^x,  1) +^ rotr($x,  8) +^ $x +> 7 }
  sub σ1 { rotr($^x, 19) +^ rotr($x, 61) +^ $x +> 6 }

  constant $K = blob64.new: init(3√*)[^80];
  my buf64 $H .= new:
  constant $  = blob64.new: init(2√*)[^8];

  my $l = 8 * my buf8 $buf .= new: $data;
  push $buf, 0x80;
  push $buf, 0 until (8*$buf - 896) %% 1024;
  push $buf, |$l.polymod(256 xx 15).reverse;

  my blob64 $words .= new: $buf.rotor(8).map: { :256[@$_] }
  loop (my int $i = 0; $i < +$words; $i += 16) {
    my buf64 $h = $H.clone;
    for ^80 -> $t {
      (state buf64 $w .= new)[$t] = (
	$t < 16 ?? $words[$t + $i] !!
	σ0($w[$t-15]) + $w[$t-7] + σ1($w[$t-2]) + $w[$t-16];
      ) % 2**64;
      my uint64 ($T1, $T2) = map *%2**64,
	$h[7] + Σ1($h[4]) + Ch(|$h[4..6]) + $K[$t] + $w[$t],
	Σ0($h[0]) + Maj(|$h[0..2]);
	
      $h[] = [ 
	($T1   + $T2) mod 2**64, $h[0], $h[1], $h[2],
	($h[3] + $T1) mod 2**64, $h[4], $h[5], $h[6]
      ];
    }
    $H[] = [map * % 2**64, ($H[] Z+ $h[])];
  }
  return blob8.new: $H.map: |*.polymod(256 xx 7).reverse;
}
