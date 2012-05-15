use Test;
use Digest;

plan 2;

is Digest::sha256::hex('foo'), '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae';
is Digest::rmd160::hex('foo'), '42cfa211018ea492fdee45ac637b7972a0ad6873';

# vim: ft=perl6
