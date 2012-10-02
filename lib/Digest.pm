module Digest;


package sha256 {
    use Digest::SHA256;
    our sub hex($data) { Digest::SHA256::hex($data) }
    our sub bin($data) { Digest::SHA256::bin($data) }
}

package rmd160 {
    use Digest::RIPEMD160;
    our sub hex($data) { Digest::RIPEMD160::hex($data) }
    our sub bin($data) { Digest::RIPEMD160::bin($data) }
}

# vim: ft=perl6
