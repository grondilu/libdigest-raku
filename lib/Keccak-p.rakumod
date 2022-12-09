unit module Keccak-p;

# CREDITS
# This is a straight-forward translation of
# https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
#


sub ROL64 { ($^a +> (64 - $_) +| $a +< $_) % (1 +< 64) given $^n%64 }

multi KeccakF1600(@lanes) {
  my $R = 1;
  for ^24 -> $round {
    # θ
    my @C = map -> $x { [+^] @lanes[$x;^5] }, ^5;
    my @D = map -> $x { @C[($x-1)%5] +^ ROL64(@C[($x+1)%5], 1) }, ^5; 
    for ^5 X ^5 -> ($x, $y) { @lanes[$x;$y] +^= @D[$x] }
    # ρ and π
    my ($x, $y) = 1, 0;
    my $current = @lanes[$x; $y];
    for ^24 -> $t {
      ($x, $y) = $y, (2*$x+3*$y)%5;
      ($current, @lanes[$x;$y]) =
      @lanes[$x;$y], ROL64 $current, ($t+1)*($t+2) div 2;
    }
    # χ
    for ^5 -> $y {
      my @T = map { @lanes[$_;$y] }, ^5;
      for ^5 -> $x {
        @lanes[$x;$y] = @T[$x] +^ (
	  +^@T[($x+1)%5] +& @T[($x+2)%5]
	);
      }
    }
    # ι
    for ^7 -> $j {
      $R = ($R +< 1 +^ (($R +> 7)*0x71)) % 256;
      if $R +& 2 { @lanes[0;0] +^= 1 +< ((1 +< $j) - 1); }
    }
  }
  return @lanes;
}

multi KeccakF1600(blob8 $state) {
  sub load64 { :256[|@^b.reverse] }
  sub store64 { $^a.polymod: 256 xx 7 }
  my @lanes;
  for ^5 X ^5 -> ($i, $j) { @lanes[$i;$j] = load64 $state.subbuf: 8*($i + 5*$j), 8; }
  KeccakF1600 @lanes;
  my buf8 $new-state .= new: 0 xx 200;
  for ^5 X ^5 -> ($i, $j) {
    given 8*($i + 5*$j) {
      $new-state[$_ ..^ $_ + 8] = store64 @lanes[$i;$j];
    }
  }
  return $new-state;
}

our sub Keccak(
  Blob $inputBytes,
  byte :$delimitedSuffix,
  UInt :$outputByteLen is copy,
  UInt :$rate where * %% 8,
  UInt :$capacity where $rate + $capacity == 1600,
) is export {

  my buf8 $outputBytes .= new;
  my buf8 $state .= new: 0 xx 200;
  my $rateInBytes = $rate div 8;
  my $blockSize = 0;
  my $inputOffset = 0;

  # === Absorb all the input blocks ===
  while $inputOffset < $inputBytes.elems {
    $blockSize = min $inputBytes - $inputOffset, $rateInBytes;
    for ^$blockSize -> $i {
      $state[$i] +^= $inputBytes[$i+$inputOffset];
    }
    $inputOffset += $blockSize;
    if $blockSize == $rateInBytes {
      $state .= &KeccakF1600;
      $blockSize = 0;
    }
  }

  # === Do the padding and switch to the squeezing phase ===
  $state[$blockSize] +^= $delimitedSuffix;
  if ($delimitedSuffix +& 0x80) != 0 and ($blockSize == ($rateInBytes-1)) {
    $state .= &KeccakF1600;
  }
  $state[$rateInBytes-1] +^= 0x80;
  $state .= &KeccakF1600;
  
  # === Squeeze out all the output blocks ===
  while $outputByteLen > 0 {
    $blockSize = min $outputByteLen, $rateInBytes;
    $outputBytes ~= $state.subbuf: 0, $blockSize;
    $outputByteLen -= $blockSize;
    $state .= &KeccakF1600 if $outputByteLen > 0;
  }
  return $outputBytes
}

