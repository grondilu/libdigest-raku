unit module Digest;

subset HexStr of Str is export where /^[<xdigit>**2]*$/ ;
 
proto md5($msg) returns Blob is export {*}
multi md5(Str $msg) { md5 $msg.encode }
multi md5(Blob $msg) {
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
  my \bits = 8 * $msg.elems;
  Blob.new: little-endian 8, 4,
    |reduce -> [$A, $B, $C, $D], blob32 $X {
      blob32.new: [$A, $B, $C, $D] Z+
        reduce -> $b, $i {
          blob32.new: 
            $b[3],
            $b[1] + ($b[0] + FGHI[$i div 16](|$b[1,2,3]) + $T[$i] + $X[@k[$i]] <<< @S[$i]),
            $b[1],
            $b[2]
        }, [$A, $B, $C, $D], |^64;
    },
    (BEGIN blob32.new: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
    |map { blob32.new: @$_ },
      blob32.new(flat(@$msg, 0x80, 0x00 xx (-(bits div 8 + 1 + 8) % 64))
        .rotor(4).map({ :256[@^a.reverse] }), little-endian(32, 2, bits)
      )
    .rotor(16);
}
 
# vi: ft=raku
