#!/usr/bin/env raku
unit module Digest::SHA3;
use Keccak-p;

our proto sha3_224($) is export {*}
our proto sha3_256($) is export {*}
our proto sha3_384($) is export {*}
our proto sha3_512($) is export {*}

multi sha3_224(Str $str) { samewith $str.encode }
multi sha3_256(Str $str) { samewith $str.encode }
multi sha3_384(Str $str) { samewith $str.encode }
multi sha3_512(Str $str) { samewith $str.encode }

multi sha3_224($inputBytes) { Keccak 1152, 448, $inputBytes, 0x06, 224 div 8 }
multi sha3_256($inputBytes) { Keccak 1088, 512, $inputBytes, 0x06, 256 div 8 }
multi sha3_384($inputBytes) { Keccak  832, 768, $inputBytes, 0x06, 384 div 8 }
multi sha3_512($inputBytes) { Keccak 576, 1024, $inputBytes, 0x06, 512 div 8 }

# vim: ft=raku
