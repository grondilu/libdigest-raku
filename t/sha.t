#!/usr/bin/env raku
use Test;
use Digest;
use Digest::SHA;

plan 6;

# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
#
is blob-to-hex(sha1(.key)), .value, "SHA-1({.key})" for
  'abc' => 'a9993e364706816aba3e25717850c26c9cd0d89d',
  'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '84983e441c3bd26ebaae4aa1f95129e5e54670f1';

is blob-to-hex(sha256(.key)), .value, "SHA-256({.key})" for
  'abc' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';

is blob-to-hex(sha512(.key)), .value, "SHA-512({.key})" for
  'abc' => 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' => '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909';

# vi: ft=raku
