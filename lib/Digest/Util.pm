module Digest::Util;

our sub rotr($n, $b) is export { $n +> $b +| $n +< (32 - $b) }
our sub rotl($n, $b) is export { $n +< $b +| $n +> (32 - $b) }

sub infix:<m+> is export { ($^x + $^y) % 2**32 }

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

# vim: ft=perl6
