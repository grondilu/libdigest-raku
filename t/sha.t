#!/usr/bin/env raku
use Test;

# SOURCES
#
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
#
# https://www.di-mgt.com.au/sha_testvectors.html
#

subtest 'SHA-1', {
  use Digest::SHA1;

  is sha1(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-1('{.key}')" for
    'abc' => 'a9993e364706816aba3e25717850c26c9cd0d89d',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '84983e441c3bd26ebaae4aa1f95129e5e54670f1';
}

subtest 'SHA-2', {
  use Digest::SHA2;

  is sha256(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-2-256('{.key}')" for
    'abc' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';

  is sha512(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-2-512('{.key}')" for
    'abc' => 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' => '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909';
}

subtest 'SHA-3', {
  use Digest::SHA3;

  is sha3_224(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-3-224('{.key}')" for
    abc => 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf',
    ''  => '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'
    ;

  is sha3_256(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-3-256('{.key}')" for
    abc => '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    ''  => 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
    ;

  is sha3_384(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-3-384('{.key}')" for
    abc => 'ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25',
    ''  => '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'
    ;

  is sha3_512(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-3-512('{.key}')" for
    abc => 'b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0',
    ''  => 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
    ;

}

done-testing;

# vi: ft=raku
