unit module Digest::RIPEMD;

=begin CREDITS
Crypto-JS v2.0.0
http:#code.google.com/p/crypto-js/
Copyright (c) 2009, Jeff Mott. All rights reserved.
=end CREDITS

BEGIN say "compiling...";
 
sub rotl(uint32 $n, $b) { $n +< $b +| $n +> (32 - $b) }
 
constant \r1 = <
    0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
    7 4 13 1 10 6 15 3 12 0 9 5 2 14 11 8
    3 10 14 4 9 15 8 1 2 7 0 6 13 11 5 12
    1 9 11 10 0 8 12 4 13 3 7 15 14 5 6 2
    4 0 5 9 7 12 2 10 14 1 3 8 11 6 15 13
>;
constant \r2 = <
    5 14 7 0 9 2 11 4 13 6 15 8 1 10 3 12
    6 11 3 7 0 13 5 10 14 15 8 12 4 9 1 2
    15 5 1 3 7 14 6 9 11 8 12 2 10 0 4 13
    8 6 4 1 3 11 15 0 5 12 2 13 9 7 10 14
    12 15 10 4 1 5 8 7 6 2 13 14 0 3 9 11
>;
constant \s1 = <
    11 14 15 12 5 8 7 9 11 13 14 15 6 7 9 8
    7 6 8 13 11 9 7 15 7 12 15 9 11 7 13 12
    11 13 6 7 14 9 13 15 14 8 13 6 5 12 7 5
    11 12 14 15 14 15 9 8 9 14 5 6 8 6 5 12
    9 15 5 11 6 8 13 12 5 12 13 14 11 8 5 6
>;
constant \s2 = <
    8 9 9 11 13 15 15 5 7 7 8 11 14 14 12 6
    9 13 15 7 12 8 9 11 7 7 12 7 6 15 13 11
    9 7 15 11 8 6 6 14 12 13 5 14 13 13 7 5
    15 5 8 11 14 14 6 14 6 9 12 9 12 5 15 8
    8 5 12 9 12 5 14 6 8 13 6 5 15 13 11 11
>;

my \F = 
    -> uint32 $x, uint32 $y, uint32 $z --> uint32 { (my uint32 $ = $x +^ $y) +^ $z },
    -> uint32 $x, uint32 $y, uint32 $z --> uint32 { (my uint32 $ = ($x +& $y)) +| (my uint32 $ = (+^$x +& $z)) },
    -> uint32 $x, uint32 $y, uint32 $z --> uint32 { (my uint32 $ = ($x +| +^$y)) +^ $z },
    -> uint32 $x, uint32 $y, uint32 $z --> uint32 { (my uint32 $ = ($x +& $z)) +| (my uint32 $ = ($y +& +^$z)) },
    -> uint32 $x, uint32 $y, uint32 $z --> uint32 { $x +^ my uint32 $ = ($y +| +^$z) }
;

constant @K1 = ((0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e) »xx» 16).map: *.Slip;
constant @K2 = ((0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000) »xx» 16).map: *.Slip;

proto rmd160($) returns Blob is export {*}
multi rmd160(Str $str where all($str.ords) < 128) { rmd160 $str.encode: 'ascii' }
multi rmd160(Blob $data) {
    my @b = flat $data.list, 0x80;
    push @b, 0 until (8*@b-448) %% 512;
    my $len = 8 * $data.elems;
    push @b, |gather for ^8 { take $len % 256; $len div= 256 }
 
    my uint32 @word = gather for @b -> $a, $b, $c, $d {
        take :256[$d, $c, $b, $a];
    }
 
    my uint32 @h = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0;
    loop (my $i = 0; $i < @word; $i += 16) {
	my uint32 @X = my uint32 @Y = @h;
	for ^80 -> $j {
	    my uint32 $T = rotl(
		@X[0] + F[$j div 16](|@X[1..3]) + (@word[$i+r1[$j]] // 0) + @K1[$j],
		s1[$j]
	    ) + @X[4];
	    my @T = @X[4], $T, @X[1], rotl(@X[2], 10), @X[3];
	    @X = [@X[4], $T, @X[1], rotl(@X[2], 10), @X[3]];
	    $T = rotl(
		@Y[0] + F[(79-$j) div 16](|@Y[1..3]) + (@word[$i+r2[$j]] // 0) + @K2[$j],
		s2[$j]
	    ) + @Y[4];
	    @Y = [@Y[4], $T, @Y[1], rotl(@Y[2], 10), @Y[3]];
	}
        @h = my uint32 @ = @h[1,2,3,4,0] Z+ @X[2,3,4,0,1] Z+ @Y[3,4,0,1,2];
    }
    return Blob.new: flat gather for @h -> $word is rw {
        for ^4 { take $word % 256; $word div= 256 }
    }
}

# vim: ft=raku
