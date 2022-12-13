unit module Digest::OpenSSL;
use NativeCall;

sub RIPEMD160  (Blob $, uint32 $, CArray[uint8] $) is native('crypto') {*}

sub SHA1  (Blob $, uint32 $, CArray[uint8] $) is native('crypto') {*}
sub SHA224(Blob $, uint32 $, CArray[uint8] $) is native('crypto') {*}
sub SHA256(Blob $, uint32 $, CArray[uint8] $) is native('crypto') {*}
sub SHA384(Blob $, uint32 $, CArray[uint8] $) is native('crypto') {*}
sub SHA512(Blob $, uint32 $, CArray[uint8] $) is native('crypto') {*}

proto rmd160($ --> Blob) is export {*}

proto sha1  ($ --> Blob) is export {*}
proto sha224($ --> Blob) is export {*}
proto sha256($ --> Blob) is export {*}
proto sha384($ --> Blob) is export {*}
proto sha512($ --> Blob) is export {*}

multi rmd160  (Str $s) { samewith $s.encode }

multi sha1  (Str $s) { samewith $s.encode }
multi sha224(Str $s) { samewith $s.encode }
multi sha256(Str $s) { samewith $s.encode }
multi sha384(Str $s) { samewith $s.encode }
multi sha512(Str $s) { samewith $s.encode }

multi rmd160(blob8 $b) { RIPEMD160   $b, my uint32 $ = $b.elems, my $output = CArray[uint8].allocate: constant $output-size = 20       ; blob8.new: $output[^$output-size]; }

multi sha1  (blob8 $b) { SHA1   $b, my uint32 $ = $b.elems, my $output = CArray[uint8].allocate: constant $output-size = 20       ; blob8.new: $output[^$output-size]; }
multi sha224(blob8 $b) { SHA224 $b, my uint32 $ = $b.elems, my $output = CArray[uint8].allocate: constant $output-size = 224 div 8; blob8.new: $output[^$output-size]; }
multi sha256(blob8 $b) { SHA256 $b, my uint32 $ = $b.elems, my $output = CArray[uint8].allocate: constant $output-size = 256 div 8; blob8.new: $output[^$output-size]; }
multi sha384(blob8 $b) { SHA384 $b, my uint32 $ = $b.elems, my $output = CArray[uint8].allocate: constant $output-size = 384 div 8; blob8.new: $output[^$output-size]; }
multi sha512(blob8 $b) { SHA512 $b, my uint32 $ = $b.elems, my $output = CArray[uint8].allocate: constant $output-size = 512 div 8; blob8.new: $output[^$output-size]; }
