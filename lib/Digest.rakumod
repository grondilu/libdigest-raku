unit module Digest;

proto md5($msg) returns Blob is export {*}
multi md5(Str $msg) { md5 $msg.encode }
multi md5(Blob $msg) {
  sub little-endian($w, $n, *@v) { (@v X+> flat ($w X* ^$n)) X% (2 ** $w) }
  my \bits = 8 * $msg.elems;
  Blob.new: little-endian 8, 4,
    |reduce -> Blob $blob, blob32 $X {
      blob32.new: $blob Z+
        reduce -> $b, $i {
          blob32.new: 
            $b[3],
            $b[1] + 
              -> uint32 \x, \n { (x +< n) +| (x +> (32-n)) }(
              $b[0] + (BEGIN Array.new:
              { ($^x +& $^y) +| (+^$x +& $^z) },
              { ($^x +& $^z) +| ($^y +& +^$z) },
              { $^x +^ $^y +^ $^z },
              { $^y +^ ($^x +| +^$^z) }
              )[$i div 16](|$b[1..3]) +
              (BEGIN blob32.new: map &floor ∘ * * 2**32 ∘ &abs ∘ &sin ∘ * + 1, ^64)[$i] +
              $X[(BEGIN Blob.new: 16 X[R%] flat ($++, 5*$++ + 1, 3*$++ + 5, 7*$++) Xxx 16)[$i]],
              (BEGIN flat < 7 12 17 22 5 9 14 20 4 11 16 23 6 10 15 21 >.rotor(4) Xxx 4)[$i]
            ),
            $b[1],
            $b[2]
        }, $blob, |^64;
    },
    (BEGIN blob32.new: 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
    |map { blob32.new: @$_ },
      blob32.new(flat(@$msg, 0x80, 0x00 xx (-(bits div 8 + 1 + 8) % 64))
        .rotor(4).map({ :256[@^a.reverse] }), |little-endian(32, 2, bits)
      )
    .rotor(16);
}
 
proto hmac(
  :$key,
  :$msg,
  :&hash,
  UInt :$block-size
) returns Blob is export {*}

multi hmac(Str :$key,     :$msg, :&hash, :$block-size) { samewith key => $key.encode, :$msg,        :&hash, :$block-size }
multi hmac(    :$key, Str :$msg, :&hash, :$block-size) { samewith       :$key,  msg => $msg.encode, :&hash, :$block-size }

multi hmac(Blob :$key is copy, Blob :$msg, :&hash, :$block-size) {
  if +$key > $block-size { $key.=&hash }
  if +$key < $block-size { $key ~= Blob.new: 0 xx ($block-size - $key) }
  reduce -> $m, $i { &hash(blob8.new(@$key Z[+^] $i xx *) ~ $m) }, $msg, 0x36, 0x5c;
}

# vi: ft=raku
