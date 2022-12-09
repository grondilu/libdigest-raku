#!/usr/bin/env raku
unit module Digest::SHA3;
use Keccak-p;

our proto sha3_224($) is export {*}
our proto sha3_256($) is export {*}
our proto sha3_384($) is export {*}
our proto sha3_512($) is export {*}
our proto shake128($, UInt $) is export {*}
our proto shake256($, UInt $) is export {*}

multi sha3_224(Str $str) { samewith $str.encode }
multi sha3_256(Str $str) { samewith $str.encode }
multi sha3_384(Str $str) { samewith $str.encode }
multi sha3_512(Str $str) { samewith $str.encode }
multi shake128(Str $str, $n) { samewith $str.encode, $n }
multi shake256(Str $str, $n) { samewith $str.encode, $n }

multi sha3_224(Blob $input) { Keccak $input, delimitedSuffix => 0x06, outputByteLen => 224 div 8, rate => 1152, capacity => 448 }
multi sha3_256(Blob $input) { Keccak $input, delimitedSuffix => 0x06, outputByteLen => 256 div 8, rate => 1088, capacity => 512 }
multi sha3_384(Blob $input) { Keccak $input, delimitedSuffix => 0x06, outputByteLen => 384 div 8, rate =>  832, capacity => 768 }
multi sha3_512(Blob $input) { Keccak $input, delimitedSuffix => 0x06, outputByteLen => 512 div 8, rate =>  576, capacity => 1024 }
multi shake128(Blob $input, UInt $outputByteLen) { Keccak $input, delimitedSuffix => 0x1F, :$outputByteLen, rate => 1344, capacity => 256 }
multi shake256(Blob $input, UInt $outputByteLen) { Keccak $input, delimitedSuffix => 0x1F, :$outputByteLen, rate => 1088, capacity => 512 }

# vim: ft=raku
