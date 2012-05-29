module Digest;
=begin credit
Crypto-JS v2.0.0
http:#code.google.com/p/crypto-js/
Copyright (c) 2009, Jeff Mott. All rights reserved.
http:#code.google.com/p/crypto-js/wiki/License
=end credit

sub rotr($n, $b) { $n +> $b +| $n +< (32 - $b) }
sub rotl($n, $b) { $n +< $b +| $n +> (32 - $b) }

sub infix:<m+> { ($^x + $^y) % 2**32 }

package util {
    #| Convert a byte array to big-endian 32-bit words
    our sub bytesToWords(@bytes) {
	my @output;
	loop (my ($i, $b) = (0, 0); $i < @bytes.elems; $i++, $b += 8) {
	    @output[$b +> 5] +|= @bytes[$i] +< (24 - $b % 32);
	}
	return @output;
    }

    #| Convert a byte array to little-endian 32-bit words
    our sub bytesToLWords(@bytes) {
	my @output = 0 xx @bytes +> 2;
	loop (my $i = 0; $i < @bytes * 8; $i += 8) {
	    @output[$i +> 5] +|= (@bytes[$i div 8] +& 0xFF) * 2**($i % 32);
	}
	return @output;
    }

    #| Convert little-endian 32-bit words to a byte array
    our sub lWordsToBytes(@words) {
	gather loop (my $i = 0; $i < @words * 32; $i += 8) {
	    take @words[$i +> 5] div 2**($i % 32) +& 0xff;
	}
    }

    #| Convert big-endian 32-bit words to a byte array
    our sub wordsToBytes(@words) {
	gather loop (my $b = 0; $b < @words.elems * 32; $b += 8) {
	    take (@words[$b +> 5] +> (24 - $b % 32)) +& 0xFF;
	}
    }
}

package sha256 {

    constant K = <
	0x428A2F98 0x71374491 0xB5C0FBCF 0xE9B5DBA5
	0x3956C25B 0x59F111F1 0x923F82A4 0xAB1C5ED5
	0xD807AA98 0x12835B01 0x243185BE 0x550C7DC3
	0x72BE5D74 0x80DEB1FE 0x9BDC06A7 0xC19BF174

	0xE49B69C1 0xEFBE4786 0x0FC19DC6 0x240CA1CC
	0x2DE92C6F 0x4A7484AA 0x5CB0A9DC 0x76F988DA
	0x983E5152 0xA831C66D 0xB00327C8 0xBF597FC7
	0xC6E00BF3 0xD5A79147 0x06CA6351 0x14292967

	0x27B70A85 0x2E1B2138 0x4D2C6DFC 0x53380D13
	0x650A7354 0x766A0ABB 0x81C2C92E 0x92722C85
	0xA2BFE8A1 0xA81A664B 0xC24B8B70 0xC76C51A3
	0xD192E819 0xD6990624 0xF40E3585 0x106AA070

	0x19A4C116 0x1E376C08 0x2748774C 0x34B0BCB5
	0x391C0CB3 0x4ED8AA4A 0x5B9CCA4F 0x682E6FF3
	0x748F82EE 0x78A5636F 0x84C87814 0x8CC70208
	0x90BEFFFA 0xA4506CEB 0xBEF9A3F7 0xC67178F2
    >;

    our proto bin($) {*}
    multi bin(Str $s) returns Buf { bin Buf.new: $s.ords }
    multi bin(Buf $data) returns Buf {
	# turning the message into an array of words
	my @word = Digest::util::bytesToWords my @b = $data.list;
	my int $l = @b * 8;

	# Padding
	@word[$l +> 5] +|= 0x80 +< (24 - $l % 32);
	@word[(($l + 64) +> 9) +< 4 + 15] = $l;

	# Initial parameters
	my @H =
	    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
	;

	my @w;
	#| Main loop
	loop (my int $i = 0; $i < @word.elems; $i = $i + 16) {
	    my @h = @H;
	    loop (my int $j = 0; $j < 64; $j = $j + 1) {
		@w[$j] = $j < 16 ?? @word[$j + $i] // 0 !!
		[m+]
		rotr(@w[$j-15], 7) +^ rotr(@w[$j-15], 18) +^ @w[$j-15] +> 3,
		@w[$j-7],
		rotr(@w[$j-2], 17) +^ rotr(@w[$j-2], 19)  +^ @w[$j-2] +> 10,
		@w[$j-16];
		my $ch = @h[4] +& @h[5] +^ +^@h[4] % 2**32 +& @h[6];
		my $maj = @h[0] +& @h[2] +^ @h[0] +& @h[1] +^ @h[1] +& @h[2];
		my $σ0 = [+^] map { rotr @h[0], $_ }, 2, 13, 22;
		my $σ1 = [+^] map { rotr @h[4], $_ }, 6, 11, 25;
		my $t1 = [m+] @h[7], $σ1, $ch, K[$j], @w[$j];
		my $t2 = $σ0 m+ $maj;
		@h = $t1 m+ $t2, @h[^3], @h[3] m+ $t1, @h[4..6];
	    }
	    @H = @H Z[m+] @h;
	}
	return Buf.new: Digest::util::wordsToBytes @H;
    }
    our sub hex($data) { [~] bin($data).list».fmt("%02x") }
}

package rmd160 {

    constant r1 = <
	0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
	7 4 13 1 10 6 15 3 12 0 9 5 2 14 11 8
	3 10 14 4 9 15 8 1 2 7 0 6 13 11 5 12
	1 9 11 10 0 8 12 4 13 3 7 15 14 5 6 2
	4 0 5 9 7 12 2 10 14 1 3 8 11 6 15 13
    >;
    constant r2 = <
	5 14 7 0 9 2 11 4 13 6 15 8 1 10 3 12
	6 11 3 7 0 13 5 10 14 15 8 12 4 9 1 2
	15 5 1 3 7 14 6 9 11 8 12 2 10 0 4 13
	8 6 4 1 3 11 15 0 5 12 2 13 9 7 10 14
	12 15 10 4 1 5 8 7 6 2 13 14 0 3 9 11
    >;
    constant s1 = <
	11 14 15 12 5 8 7 9 11 13 14 15 6 7 9 8
	7 6 8 13 11 9 7 15 7 12 15 9 11 7 13 12
	11 13 6 7 14 9 13 15 14 8 13 6 5 12 7 5
	11 12 14 15 14 15 9 8 9 14 5 6 8 6 5 12
	9 15 5 11 6 8 13 12 5 12 13 14 11 8 5 6
    >;
    constant s2 = <
	8 9 9 11 13 15 15 5 7 7 8 11 14 14 12 6
	9 13 15 7 12 8 9 11 7 7 12 7 6 15 13 11
	9 7 15 11 8 6 6 14 12 13 5 14 13 13 7 5
	15 5 8 11 14 14 6 14 6 9 12 9 12 5 15 8
	8 5 12 9 12 5 14 6 8 13 6 5 15 13 11 11
    >;
    sub f($j, $x, $y, $z) {
	return
	$j < 16 ?? $x +^ $y +^ $z !!
	$j < 32 ?? ($x +& $y) +| (+^$x % 2**32 +& $z) !!
	$j < 48 ?? ($x +| +^$y % 2**32) +^ $z !!
	$j < 64 ?? ($x +& $z) +| ($y +& (+^$z % 2**32)) !!
	$j < 80 ?? $x +^ ($y +| +^$z % 2**32) !!
	!!! "out of range";
    }
    sub K1($j) {
	return
	$j < 16 ?? 0x00000000 !!
	$j < 32 ?? 0x5a827999 !!
	$j < 48 ?? 0x6ed9eba1 !!
	$j < 64 ?? 0x8f1bbcdc !!
	$j < 80 ?? 0xa953fd4e !!
	!!! "out of range";
    }
    sub K2($j) {
	return
	$j < 16 ?? 0x50a28be6 !!
	$j < 32 ?? 0x5c4dd124 !!
	$j < 48 ?? 0x6d703ef3 !!
	$j < 64 ?? 0x7a6d76e9 !!
	$j < 80 ?? 0x00000000 !!
	!!! "out of range";
    }
    our proto bin($) {*}
    multi bin(Str $s) returns Buf { bin Buf.new: $s.ords }
    multi bin(Buf $data) returns Buf {
	my @word = Digest::util::bytesToLWords my @b = $data.list;
	my $len = @b * 8;

	@word[$len +> 5] +|= 0x80 +< ($len % 32);
	@word[((($len + 64) +> 9) +< 4) + 14] = $len;

	my @h = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0;
	loop (my int $i = 0; $i < @word; $i = $i + 16) {
	    my @X = my @Y = @h;
	    loop (my $j = 0; $j < 80; $j = $j + 1) {
		my $T = rotl(
		    @X[0] m+ f($j, |@X[1..3]) m+ (@word[$i+r1[$j]] // 0) m+ K1($j),
		    s1[$j]
		) m+ @X[4];
		@X = @X[4], $T, @X[1], rotl(@X[2], 10) % 2**32, @X[3];
		$T = rotl(
		    @Y[0] m+ f(79-$j, |@Y[1..3]) m+ (@word[$i+r2[$j]] // 0) m+ K2($j),
		    s2[$j]
		) m+ @Y[4];
		@Y = @Y[4], $T, @Y[1], rotl(@Y[2], 10) % 2**32, @Y[3];
	    }
	    @h = @h[1..4,^1] Z[m+] @X[2..4,^2] Z[m+] @Y[3..4,^3];
	}
	return Buf.new: Digest::util::lWordsToBytes @h;
    }
    our sub hex($data) returns Str { [~] bin($data).list».fmt("%02x") }

}
