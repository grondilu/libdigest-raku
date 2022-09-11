#!/usr/bin/env raku
use Test;
use Digest;
use Digest::SHA;

# SOURCES
#
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
#
# https://www.di-mgt.com.au/sha_testvectors.html
#

subtest 'SHA-1', {
  is blob-to-hex(sha1(.key)), .value, "SHA-1({.key})" for
    'abc' => 'a9993e364706816aba3e25717850c26c9cd0d89d',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '84983e441c3bd26ebaae4aa1f95129e5e54670f1';
}

subtest 'SHA-2', {
is blob-to-hex(sha256(.key)), .value, "SHA-2-256({.key})" for
  'abc' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';

is blob-to-hex(sha512(.key)), .value, "SHA-2-512({.key})" for
  'abc' => 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' => '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909';
}

subtest 'SHA-3', {

  is blob-to-hex(sha3_224(.key)), .value, "SHA-3-224({.key})" for
    abc => 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    ''  => '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'
    ;

  is blob-to-hex(sha3_256(.key)), .value, "SHA-3-256({.key})" for
    abc => '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    ''  => 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
    ;

}

done-testing;

# vi: ft=raku
