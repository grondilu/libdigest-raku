#/usr/bin/env raku
# https://www.rfc-editor.org/rfc/rfc4231
#
use Test;
use Digest;
use Digest::SHA2;

sub hex-to-blob { blob8.new: $^str.comb(/../).map({:16($_)}) }

constant %sha224 = hash => sub {...}, block-size => UInt;
constant %sha256 = hash => &sha256, block-size => 64;
constant %sha384 = hash => sub {...}, block-size => UInt;
constant %sha512 = hash => &sha512, block-size => 128;

subtest {
  my ($key, $msg) = Blob.new(0x0b xx 20), "Hi There";

  skip "SHA-224 NYI";
  =for sha224
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      896fb1128abbdf196832107cd49df33f
      47b4b1169912ba4f53684b22
    >.join
  ;
    
  is hmac(:$key, :$msg, |%sha256),
    hex-to-blob <
      b0344c61d8db38535ca8afceaf0bf12b
      881dc200c9833da726e9376c2e32cff7
    >.join
  ;
    
  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      afd03944d84895626b0825f4ab46907f
      15f9dadbe4101ec682aa034c7cebc59c
      faea9ea9076ede7f4af152e8b2fa9cb6
    >.join
  ;
    
  is hmac(:$key, :$msg, |%sha512),
    hex-to-blob <
      87aa7cdea5ef619d4ff0b4241a1d6cb0
      2379f4e2ce4ec2787ad0b30545e17cde
      daa833b7d6b8a702038b274eaea3f4e4
      be9d914eeb61f1702e696c203a126854
    >.join
  ;
	      
}

subtest  {
  my ($key, $msg) = "Jefe", "what do ya want for nothing?";

  skip "SHA-224 NYI";
  =for sha224
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      a30e01098bc6dbbf45690f3a7e9e6d0f
      8bbea2a39e6148008fd05e44
    >.join
  ;
    
  is hmac(:$key, :$msg, |%sha256),
    hex-to-blob <
      5bdcc146bf60754e6a042426089575c7
      5a003f089d2739839dec58b964ec3843
    >.join
  ;
    
  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      af45d2e376484031617f78d2b58a6b1b
      9c7ef464f5a01b47e42ec3736322445e
      8e2240ca5e69e2c78b3239ecfab21649
    >.join
  ;
    
is hmac(:$key, :$msg, |%sha512),
    hex-to-blob <
      164b7a7bfcf819e2e395fbe73b56e0a3
      87bd64222e831fd610270cd7ea250554
      9758bf75c05a994a6d034f65f8f0e6fd
      caeab1a34d4a6b4b636e070a38bce737
    >.join
  ;
	      
}

subtest {
  my ($key, $msg) = Blob.new(0xaa xx 20), Blob.new(0xdd xx 50);

  skip "SHA-224 NYI";
  =for sha224
    is hmac(:$key, :$msg, |%sha224),
      hex-to-blob <
        7fb3cb3588c6c1f6ffa9694d7d6ad264
	9365b0c1f65d69d1ec8333ea
    >.join
    ;

  is hmac(:$key, :$msg, |%sha256),
    hex-to-blob <
      773ea91e36800e46854db8ebd09181a7
      2959098b3ef8c122d9635514ced565fe
    >.join
  ;

  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      88062608d3e6ad8a0aa2ace014c8a86f
      0aa635d947ac9febe83ef4e55966144b
      2a5ab39dc13814b94e3ab6e101a34f27
    >.join
    ;

  is hmac(:$key, :$msg, |%sha512),
    hex-to-blob <
      fa73b0089d56a284efb0f0756c890be9
      b1b5dbdd8ee81a3655f83e33b2279d39
      bf3e848279a722c806b485a47e67c807
      b946a337bee8942674278859e13292fb
   >.join
   ;

}

subtest {
  my ($key, $msg) = Blob.new(1..25), Blob.new(0xcd xx 50);

  skip "SHA-224 NYI";
  =for sha224
    is hmac(:$key, :$msg, |%sha224),
      hex-to-blob <
        6c11506874013cac6a2abc1bb382627c
	ec6a90d86efc012de7afec5a
    >.join
    ;

  is hmac(:$key, :$msg, |%sha256),
    hex-to-blob <
      82558a389a443c0ea4cc819899f2083a
      85f0faa3e578f8077a2e3ff46729665b
    >.join
  ;

  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      3e8a69b7783c25851933ab6290af6ca7
      7a9981480850009cc5577c6e1f573b4e
      6801dd23c4a7d679ccf8a386c674cffb
    >.join
    ;

  is hmac(:$key, :$msg, |%sha512),
    hex-to-blob <
      b0ba465637458c6990e5a8c5f61d4af7
      e576d97ff94b872de76f8050361ee3db
      a91ca5c11aa25eb4d679275cc5788063
      a5f19741120c4f2de2adebeb10a298dd
   >.join
   ;

}

subtest {
  my ($key, $msg) = Blob.new(0x0c xx 20), "Test With Truncation";

  skip "SHA-224 NYI";
  =for sha224
    is hmac(:$key, :$msg, |%sha224).subbuf(0,16),
      hex-to-blob "0e2aea68a90c8d37c988bcdb9fca6fa8"
  ;

  is hmac(:$key, :$msg, |%sha256).subbuf(0,16),
    hex-to-blob "a3b6167473100ee06e0c796c2955552b"
  ;

  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224).subbuf(0,16),
    hex-to-blob "3abf34c3503b2a23a46efc619baef897"
    ;

  is hmac(:$key, :$msg, |%sha512).subbuf(0,16),
    hex-to-blob "415fad6271580a531d4179bc891d87a6"
  ;

}

subtest {
  my ($key, $msg) = blob8.new(0xaa xx 131),
    "Test Using Larger Than Block-Size Key - Hash Key First";

  skip "SHA-224 NYI";
  =for sha224
    is hmac(:$key, :$msg, |%sha224),
      hex-to-blob <
        95e9a0db962095adaebe9b2d6f0dbce2
	d499f112f2d2b7273fa6870e
    >.join
    ;

  is hmac(:$key, :$msg, |%sha256),
    hex-to-blob <
      60e431591ee0b67f0d8a26aacbf5b77f
      8e0bc6213728c5140546040f0ee37f54
    >.join
  ;

  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      4ece084485813e9088d2c63a041bc5b4
      4f9ef1012a2b588f3cd11f05033ac4c6
      0c2ef6ab4030fe8296248df163f44952
    >.join
    ;

  is hmac(:$key, :$msg, |%sha512),
    hex-to-blob <
      80b24263c7c1a3ebb71493c1dd7be8b4
      9b46d1f41b4aeec1121b013783f8f352
      6b56d037e05f2598bd0fd2215d6a1e52
      95e64f73f63f0aec8b915a985d786598
   >.join
   ;

}

subtest {
  my ($key, $msg) = blob8.new(0xaa xx 131),
    (
      "This is a test u",
      "sing a larger th",
      "an block-size ke",
      "y and a larger t",
      "han block-size d",
      "ata. The key nee",
      "ds to be hashed ",
      "before being use",
      "d by the HMAC al",
      "gorithm.",
    ).join;

  skip "SHA-224 NYI";
  =for sha224
    is hmac(:$key, :$msg, |%sha224),
      hex-to-blob <
        3a854166ac5d9f023f54d517d0b39dbd
                  946770db9c2b95c9f6f565d1
    >.join
    ;

  is hmac(:$key, :$msg, |%sha256),
    hex-to-blob <
      9b09ffa71b942fcb27635fbcd5b0e944
      bfdc63644f0713938a7f51535c3a35e2
    >.join
  ;

  skip "SHA-384 NYI";
  =for sha384
  is hmac(:$key, :$msg, |%sha224),
    hex-to-blob <
      6617178e941f020d351e2f254e8fd32c
      602420feb0b8fb9adccebb82461e99c5
      a678cc31e799176d3860e6110c46523e
    >.join
    ;

  is hmac(:$key, :$msg, |%sha512),
    hex-to-blob <
      e37b6a775dc87dbaa4dfa9f96e5e3ffd
      debd71f8867289865df5a32d20cdc944
      b6022cac3c4982b10d5eeb55c3e4de15
      134676fb6de0446065c97440fa8c6a58
   >.join
   ;

}

done-testing;
# vi: ft=raku
