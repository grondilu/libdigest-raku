use v6;
use Test;
use Digest;

plan my $plan = 10;

my @abc = ^10, 'a' .. 'z', 'A' .. 'Z', <_ + - . = % * / ! |>;
for ^$plan {
    my $s = [~] time, map {@abc.pick}, ^((1000*rand).Int);
    is(
	Digest::sha256::hex($s),
	qqx{perl -e "use Digest::SHA; print Digest::SHA::sha256_hex q($s)"}
    );
}

# vim: ft=perl6
