unit module Digest::SHA;

=begin Credits
The code for SHA-1 comes from Rosetta code:

L<http://rosettacode.org/wiki/SHA-1#Perl_6>

The code for SHA-256 comes from a javascript implementation:

Crypto-JS v2.0.0
http:#code.google.com/p/crypto-js/
Copyright (c) 2009, Jeff Mott. All rights reserved.
http:#code.google.com/p/crypto-js/wiki/License

It was heavily modified, though.
=end Credits

my \primes = grep(*.is-prime, 2 .. *).list;

sub postfix:<mod2³²>(\x) { x % 2**32 }
sub infix:<⊕>(\x,\y)     { (x + y)mod2³² }
sub S(\n,\X)             { (X +< n)mod2³² +| (X +> (32-n)) }
 
my \f = -> \B,\C,\D { (B +& C) +| ((+^B)mod2³² +& D)   },
        -> \B,\C,\D { B +^ C +^ D                      },
        -> \B,\C,\D { (B +& C) +| (B +& D) +| (C +& D) },
        -> \B,\C,\D { B +^ C +^ D                      };
 
my \K = 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6;
 
sub sha1-pad(Blob $msg)
{
    my \bits = 8 * $msg.elems;
    my @padded = flat $msg.list, 0x80, 0x00 xx (-(bits div 8 + 1 + 8) % 64);
    flat @padded.map({ :256[$^a,$^b,$^c,$^d] }), (bits +> 32)mod2³², (bits)mod2³²;
}
 
sub sha1-block(@H, @M)
{
    my @W = @M;
    @W.push: S(1, @W[$_-3] +^ @W[$_-8] +^ @W[$_-14] +^ @W[$_-16]) for 16..79;
 
    my ($A,$B,$C,$D,$E) = @H;
    for 0..79 -> \t {
        my \TEMP = S(5,$A) ⊕ f[t div 20]($B,$C,$D) ⊕ $E ⊕ @W[t] ⊕ K[t div 20];
        $E = $D; $D = $C; $C = S(30,$B); $B = $A; $A = TEMP;
    }
    @H «⊕=» ($A,$B,$C,$D,$E);
}
 
proto sha1($) returns Blob is export {*}
multi sha1(Str $str where all($str.ords) < 128 ) { sha1 $str.encode: 'ascii' }
multi sha1(Blob $msg) {
    my @M = sha1-pad($msg);
    my @H = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0;
    sha1-block(@H,@M[$_..$_+15]) for 0,16...^+@M;
    Blob.new: gather for @H {
        my $h = $_;
        for 256 «**« reverse ^4 {
            take $h div $_; $h mod= $_;
        }
    }
}

sub init(&f) { map { (($_ - .Int)*2**32).Int }, map &f, primes }

sub rotr(uint32 $n, uint32 $b) { $n +> $b +| $n +< (32 - $b) }
 
proto sha256($) returns Blob is export {*}
multi sha256(Str $str where all($str.ords) < 128 ) { sha256 $str.encode: 'ascii' }
my $K = init(* **(1/3))[^64];
multi sha256(Blob $data) {
    my $l = 8 * my @b = $data.list;
    # The message is padded with a single 1 bit, and then zero bits until the
    # length (in bits) is 448 mod 512.
    push @b, 0x80;
    push @b, 0 until (8*@b-448) %% 512;

    # The length of the message is pushed, with an eight bytes encoding
    push @b, |$l.polymod(256 xx 7).reverse;

    # the message is turned into a list of eight-bytes words
    my @word = @b.rotor(4).map: { :256[@$_] }

    my @H = init(&sqrt)[^8];
    my @w;

    loop (my int $i = 0; $i < @word.elems; $i = $i + 16) {
        my @h = @H;
        loop (my int $j = 0; $j < 64; $j = $j + 1) {
            @w.AT-POS($j) = $j < 16 ?? @word.AT-POS($j + $i) // 0 !!
                (rotr(@w.AT-POS($j-15), 7) +^ rotr(@w.AT-POS($j-15), 18) +^ @w.AT-POS($j-15) +> 3) ⊕
                @w.AT-POS($j-7) ⊕
                (rotr(@w.AT-POS($j-2), 17) +^ rotr(@w.AT-POS($j-2), 19)  +^ @w.AT-POS($j-2) +> 10) ⊕
                @w.AT-POS($j-16);
            my $ch = @h.AT-POS(4) +& @h.AT-POS(5) +^ +^@h.AT-POS(4) % 2**32 +& @h.AT-POS(6);
            my $maj = @h.AT-POS(0) +& @h.AT-POS(2) +^ @h.AT-POS(0) +& @h.AT-POS(1) +^ @h.AT-POS(1) +& @h.AT-POS(2);
            my $σ0 = rotr(@h.AT-POS(0), 2) +^ rotr(@h.AT-POS(0), 13) +^ rotr(@h.AT-POS(0), 22);
            my $σ1 = rotr(@h.AT-POS(4), 6) +^ rotr(@h.AT-POS(4), 11) +^ rotr(@h.AT-POS(4), 25);
            my $t1 = @h.AT-POS(7) ⊕ $σ1 ⊕ $ch ⊕ $K.AT-POS($j) ⊕ @w.AT-POS($j);
            my $t2 = $σ0 ⊕ $maj;
            @h = $t1 ⊕ $t2, @h.AT-POS(0), @h.AT-POS(1), @h.AT-POS(2),
                @h.AT-POS(3) ⊕ $t1, @h.AT-POS(4), @h.AT-POS(5), @h.AT-POS(6);
        }
        @H = @H Z⊕ @h;
    }
    return Blob.new: flat @H.map: *.polymod(256 xx 3).reverse;
}

# vim: ft=perl6
