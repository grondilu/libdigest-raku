unit module Digest;

subset HexStr of Str is export where /^<xdigit>*$/ ;
sub blob-to-hex(Blob $b) returns HexStr is export { $b».fmt("%02x").join }

sub infix:«<<<»(uint32 \x, \n) returns uint32 { my uint32 $ = (x +< n) +| (x +> (32-n)) }
 
my \FGHI = sub (uint32 $x, uint32 $y, uint32 $z) { ($x +& $y) +| (+^$x +& $z) },
                -> \X, \Y, \Z { my uint32 $ = (X +& Z) +| (Y +& +^Z) },
                -> \X, \Y, \Z { my uint32 $ = X +^ Y +^ Z           },
                sub (uint32 $x, uint32 $y, uint32 $z) { my uint32 $ = $y +^ ($x +| +^$z) };
 
my \S = ((7, 12, 17, 22) xx 4,
             (5,  9, 14, 20) xx 4,
             (4, 11, 16, 23) xx 4,
             (6, 10, 15, 21) xx 4).flat;
 
my uint32 @T = (floor(abs(sin($_ + 1)) * 2**32) for ^64);
 
my \k = ((   $_           for ^16),
             ((5*$_ + 1) % 16 for ^16),
             ((3*$_ + 5) % 16 for ^16),
             ((7*$_    ) % 16 for ^16)).flat;
 
sub little-endian($w, $n, *@v) { (@v X+> flat ($w X* ^$n)) X% (2 ** $w) }
 
sub md5-pad(Blob $msg)
{
    my \bits = 8 * $msg.elems;
    my @padded = flat $msg.list, 0x80, 0x00 xx (-(bits div 8 + 1 + 8) % 64);
    my uint32 @ =
    flat @padded.map({ :256[$^d,$^c,$^b,$^a] }), little-endian(32, 2, bits);
}
 
sub md5-block(uint32 @H, uint32 @X)
{
    my uint32 ($A, $B, $C, $D) = @H;
    for ^64 -> $i {
        my uint32 $f = FGHI[$i div 16]($B, $C, $D);
          ($A, $B,                                         $C, $D)
        = ($D, $B + (($A + $f + @T[$i] + @X[k[$i]]) <<< S[$i]), $B, $C);
    }
    @H «+=» ($A, $B, $C, $D);
}
 
proto md5($msg) returns Blob is export {*}
multi md5(Str $msg) { md5 $msg.encode }
multi md5(Blob $msg) {
    my uint32 @M = md5-pad($msg);
    my uint32 @H = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476;
    md5-block(@H, @M[$_ .. $_+15]) for 0, 16 ...^ +@M;
    Blob.new: little-endian(8, 4, @H);
}
 
# vi: ft=raku
