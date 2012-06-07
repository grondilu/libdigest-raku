module Digest::sha256;
use Digest::util;

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

# vim: ft=perl6
