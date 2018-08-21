<?php
declare(strict_types=1);

namespace Mdanter\Ecc\Tests\Crypto\Signature;

use Mdanter\Ecc\Crypto\Signature\SignHasher;
use Mdanter\Ecc\Tests\AbstractTestCase;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\Math\GmpMath;
use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;

class SignerTest extends AbstractTestCase
{
    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Unsupported hashing algorithm
     */
    public function testInvalidHashAlgorithm()
    {
        new SignHasher("blahblah");
    }

    public function testSignatureRValueMayBe1()
    {
        $math = new GmpMath();
        $ser = new Signature(gmp_init(1), gmp_init(2));
        $pubKeyHex = '30819b301006072a8648ce3d020106052b810400230381860004001fb7064274ba3b5950f00a027cb2cf42d1ed69c89d944da0415e9086f35c85b44afdd635cdc1fade2ce71e62485e243ceb9f075a111476302e60d7d78b1207cda7006b4252077172332059a9c60f966893fda7e73377debcba9a8f69cee8f59d67a2ca892fad1df4463161f157c7c117c1bbfddc88441c4c8abc63667be5c1ff22f6e2';
        $data = '54657374';
        $curve = NistCurve::NAME_P521;
        $hashAlg = 'sha512';

        $G = CurveFactory::getGeneratorByName($curve);
        $pubKeySer = new DerPublicKeySerializer($math);
        $pubKey = $pubKeySer->parse(hex2bin($pubKeyHex));
        $signer = new Signer($math);
        $hasher = new SignHasher($hashAlg);
        $hash = $hasher->makeHash(hex2bin($data), $G);
        $this->assertTrue($signer->verify($pubKey, $ser, $hash));
    }

    public function testSignatureSValueMayBe1()
    {
        $math = new GmpMath();
        $ser = new Signature(gmp_init(5), gmp_init(1));
        $pubKeyHex = '3059301306072a8648ce3d020106082a8648ce3d030107034200044a03ef9f92eb268cafa601072489a56380fa0dc43171d7712813b3a19a1eb5e53e213e28a608ce9a2f4a17fd830c6654018a79b3e0263d91a8ba90622df6f2f0';
        $data = '54657374';
        $curve = NistCurve::NAME_P256;
        $hashAlg = 'sha256';

        $G = CurveFactory::getGeneratorByName($curve);
        $pubKeySer = new DerPublicKeySerializer($math);
        $pubKey = $pubKeySer->parse(hex2bin($pubKeyHex));
        $signer = new Signer($math);
        $hasher = new SignHasher($hashAlg);
        $hash = $hasher->makeHash(hex2bin($data), $G);
        $this->assertTrue($signer->verify($pubKey, $ser, $hash));
    }
}
