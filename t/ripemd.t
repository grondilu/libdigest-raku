use Test;
use Digest::RIPEMD;

my $test-buf = "foo bar".encode: 'ascii';
my $rmd160 = rmd160 $test-buf;

plan 1;

is $rmd160.list».fmt("%02x").join, 'daba326b8e276af34297f879f6234bcef2528efa', "rmd160";
# vim: ft=perl6
