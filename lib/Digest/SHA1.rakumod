#!/usr/bin/env raku
unit module Digest::SHA1;

proto sha1($)   returns blob8 is export {*}

multi sha1  (Str $str) { samewith $str.encode }

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
