#!/usr/bin/env raku
use Test;

# SOURCES
#
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA1.pdf
# https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
#
# https://www.di-mgt.com.au/sha_testvectors.html
#

use Digest::OpenSSL;

subtest 'SHA-1', {

  is Digest::OpenSSL::sha1(.key), Blob.new(parse-base(.value, 16).polymod(256 xx *).reverse), "SHA-1('{.key}')" for
    'abc' => 'a9993e364706816aba3e25717850c26c9cd0d89d',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '84983e441c3bd26ebaae4aa1f95129e5e54670f1';

}

subtest 'SHA-2', {

  is Digest::OpenSSL::sha224(.key), Blob.new(.value.comb(/../).map(*.parse-base(16))), "SHA-2-224('{.key}')" for
    '' => 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
    'abc' => '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525';

  is Digest::OpenSSL::sha256(.key), Blob.new(.value.comb(/../).map(*.parse-base(16))), "SHA-2-256('{.key}')" for
    'abc' => 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' => '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';

  is Digest::OpenSSL::sha384(.key), Blob.new(.value.comb(/../).map(*.parse-base(16))), "SHA-2-384('{.key}')" for
    'abc' => 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' => '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039';

  is Digest::OpenSSL::sha512(.key), Blob.new(.value.comb(/../).map(*.parse-base(16))), "SHA-2-512('{.key}')" for
    'abc' => 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' => '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909';
    
}

done-testing;

# vi: ft=raku
