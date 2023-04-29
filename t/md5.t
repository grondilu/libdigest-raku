#!/usr/bin/env raku
use Test;
use lib <lib>;
use Digest::MD5;

subtest 'rfc1321', {
  for
    'd41d8cd98f00b204e9800998ecf8427e', '',
    '0cc175b9c0f1b6a831c399e269772661', 'a',
    '900150983cd24fb0d6963f7d28e17f72', 'abc',
    'f96b697d7cb7938d525a2f31aaf161d0', 'message digest',
    'c3fcd3d76192e4007dfb496cca67e13b', 'abcdefghijklmnopqrstuvwxyz',
    'd174ab98d277d9f5a5611c2c9f419d9f', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
    '57edf4a22be3c955ac49da2e2107b67a', '12345678901234567890123456789012345678901234567890123456789012345678901234567890'
    -> $expected, $msg {
      is
	md5($msg),
	Blob.new(parse-base($expected, 16).polymod(256 xx *).reverse),
	"md5('$msg') is '$expected'";
  }
}

subtest 'hash 100 random strings', {
  for ^100 {
    my $str = ("a".."z").roll(8).join;
    lives-ok { md5 $str }, $str;
  }
}
done-testing;

# vim: ft=raku
