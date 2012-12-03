module Digest::SSL;
use NativeCall;

constant little-endian = 1;

sub SHA256(    Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub RIPEMD160( Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }

sub int2list(int $i) {
    my $n = $i < 0 ?? 256**4 + $i !! $i;
    my @a = map { $n div 256**$_ % 256 }, ^4;
    little-endian ?? @a !! reverse @a;
}

package sha256 {
    our sub hex($s) {
	my @a := SHA256( $s , $s.chars, Any );
	join "", map { sprintf "%02x" x 4, int2list $_ }, @a[^8];
    }
    our sub bin($s) {
	my @a := SHA256( $s , $s.chars, Any );
	Buf.new: map { int2list $_ }, @a[^8];
    }
}

say sha256::bin "foo";

=begin END
2c26b46b6800c790f99b453c1d30413413422d706484c0a1f98b5f896267e8af
2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae  -
# vim: ft=perl6
