#!/usr/bin/env raku
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

proto sha1($)   returns blob8 is export {*}
proto sha256($) returns blob8 is export {*}
proto sha512($) returns blob8 is export {*}

proto hmac-sha1  ($, $) returns blob8 is export {*}
proto hmac-sha256($, $) returns blob8 is export {*}
proto hmac-sha512($, $) returns blob8 is export {*}

multi sha1  (Str $str) { samewith $str.encode }
multi sha256(Str $str) { samewith $str.encode }
multi sha512(Str $str) { samewith $str.encode }

multi hmac-sha1  (Str   $a,       $b) { samewith $a.encode, $b }
multi hmac-sha1  (blob8 $a, Str   $b) { samewith $a, $b.encode }
multi hmac-sha256(Str   $a,       $b) { samewith $a.encode, $b }
multi hmac-sha256(blob8 $a, Str   $b) { samewith $a, $b.encode }
multi hmac-sha512(Str   $a,       $b) { samewith $a.encode, $b }
multi hmac-sha512(blob8 $a, Str   $b) { samewith $a, $b.encode }

my \primes = grep(*.is-prime, 2 .. *).list;

sub postfix:<mod2³²>(\x) { x % 2**32 }
sub infix:<⊕>(\x,\y)     { (x + y)mod2³² }
sub S(\n,\X)             { (X +< n)mod2³² +| (X +> (32-n)) }
 
my \f = -> \B,\C,\D { (B +& C) +| ((+^B)mod2³² +& D)   },
        -> \B,\C,\D { B +^ C +^ D                      },
        -> \B,\C,\D { (B +& C) +| (B +& D) +| (C +& D) },
        -> \B,\C,\D { B +^ C +^ D                      };
 
my \K = 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6;
 
sub sha1-pad(blob8 $msg)
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
 
multi sha1(blob8 $msg) {
    my @M = sha1-pad($msg);
    my @H = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0;
    sha1-block(@H,@M[$_..$_+15]) for 0,16...^+@M;
    blob8.new: gather for @H {
        my $h = $_;
        for 256 «**« reverse ^4 {
            take $h div $_; $h mod= $_;
        }
    }
}

sub init(&f) { map { (($_ - .Int)*2**32).Int }, map &f, primes }

sub rotr(uint32 $n, uint32 $b) { $n +> $b +| $n +< (32 - $b) }
 
my $K = init(* **(1/3))[^64];
multi sha256(blob8 $data) {
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

    loop (my int $i = 0; $i < @word; $i += 16) {
        my @h = @H;
        loop (my int $j = 0; $j < 64; $j += 1) {
            @w[$j] = $j < 16 ?? @word[$j + $i] // 0 !!
                (rotr(@w[$j-15], 7) +^ rotr(@w[$j-15], 18) +^ @w[$j-15] +> 3) ⊕
                @w[$j-7] ⊕
                (rotr(@w[$j-2], 17) +^ rotr(@w[$j-2], 19)  +^ @w[$j-2] +> 10) ⊕
                @w[$j-16];
            my $ch = @h[4] +& @h[5] +^ +^@h[4] % 2**32 +& @h[6];
            my $maj = @h[0] +& @h[2] +^ @h[0] +& @h[1] +^ @h[1] +& @h[2];
            my $σ0 = rotr(@h[0], 2) +^ rotr(@h[0], 13) +^ rotr(@h[0], 22);
            my $σ1 = rotr(@h[4], 6) +^ rotr(@h[4], 11) +^ rotr(@h[4], 25);
            my $t1 = @h[7] ⊕ $σ1 ⊕ $ch ⊕ $K[$j] ⊕ @w[$j];
            my $t2 = $σ0 ⊕ $maj;
            @h = $t1 ⊕ $t2, @h[0], @h[1], @h[2],
                @h[3] ⊕ $t1, @h[4], @h[5], @h[6];
        }
        @H [Z⊕]= @h;
    }
    return blob8.new: flat @H.map: *.polymod(256 xx 3).reverse;
}

multi sha512(blob8 $b) {
  given run <openssl dgst -sha512 -binary>, :in, :out, :bin {
    .in.write: $b;
    .in.close;
    return .out.slurp: :close;
  }
}

multi hmac-sha1(blob8 $a, blob8 $b) {
  my $hexkey = $b».fmt("%02x").join;
  given run |qqw{openssl mac -binary -digest SHA1 -macopt hexkey:$hexkey -in - HMAC},
    :in, :out, :bin {
    .in.write: $a;
    .in.close;
    return .out.slurp: :close;
  }
}

multi hmac-sha256(blob8 $a, blob8 $b) {
  my $hexkey = $b».fmt("%02x").join;
  given run |qqw{openssl mac -binary -digest SHA256 -macopt hexkey:$hexkey -in - HMAC},
    :in, :out, :bin {
    .in.write: $a;
    .in.close;
    return .out.slurp: :close;
  }
}

multi hmac-sha512(blob8 $a, blob8 $b) {
  given run |<openssl dgst -sha512 -mac hmac -binary -macopt>,
    "hexkey:{$b».fmt("%02x").join}", :in, :out, :bin {
    .in.write: $a;
    .in.close;
    return .out.slurp: :close;
  }
}

# vim: ft=raku
