unit module Digest;

subset HexStr of Str is export where /^[<xdigit>**2]*$/ ;
sub blob-to-hex(Blob $b) returns HexStr is export { $b».fmt("%02x").join }

sub infix:«<<<»(uint32 \x, \n) returns uint32 { (x +< n) +| (x +> (32-n)) }
 
my \FGHI = { ($^x +& $^y) +| (+^$x +& $^z) },
	   { ($^x +& $^z) +| ($^y +& +^$z) },
	   { $^x +^ $^y +^ $^z },
	   { $^y +^ ($^x +| +^$^z) };
 
constant @S = flat < 7 12 17 22 5 9 14 20 4 11 16 23 6 10 15 21 >.rotor(4) X[xx] 4;
 
constant $T = blob32.new: ^64 .map: { floor(abs(sin($_ + 1)) * 2**32) };
 
constant @k = flat ^16,
             ((5*$_ + 1) % 16 for ^16),
             ((3*$_ + 5) % 16 for ^16),
             ((7*$_    ) % 16 for ^16);
 
sub little-endian($w, $n, *@v) { (@v X+> flat ($w X* ^$n)) X% (2 ** $w) }
 
sub md5-pad(Blob $msg --> blob32)
{
    my \bits = 8 * $msg.elems;
    my @padded = flat $msg.list, 0x80, 0x00 xx (-(bits div 8 + 1 + 8) % 64);
    blob32.new: |@padded.rotor(4).map({ :256[@^a.reverse] }), little-endian(32, 2, bits);
}
 
sub md5-block(buf32 $H is rw, blob32 $X)
{
    my buf32 $h .= new: @$H;
    for ^64 -> $i {
	$h[] = [
	  $h[3], $h[1] + ($h[0] + FGHI[$i div 16](|$h[1,2,3]) + $T[$i] + $X[@k[$i]] <<< @S[$i]), $h[1], $h[2]
	]
    }
    $H[] Z[+=] @$h
}
 
proto md5($msg) returns Blob is export {*}
multi md5(Str $msg) { md5 $msg.encode }
multi md5(Blob $msg) {
    my blob32 $M = md5-pad($msg);
    my buf32 $H .= new: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476;
    md5-block($H, $M.subbuf($_, 16)) for 0, 16 ...^ +$M;
    Blob.new: little-endian 8, 4, @$H;
}
 
# vi: ft=raku
