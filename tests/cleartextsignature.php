<?php

require_once dirname(__FILE__).'/../lib/openpgp.php';
require_once dirname(__FILE__).'/../lib/openpgp_crypt_rsa.php';
require_once dirname(__FILE__).'/../lib/openpgp_crypt_symmetric.php';

class CleartextSignature extends PHPUnit_Framework_TestCase {

    public function dataUnescapeGood() {
        return array(
            array("- -- bla", "-- bla"),
            array("blubber\n- -- bla", "blubber\n-- bla"),
            array("blubber\n- -- bla\n- - test\nend", "blubber\n-- bla\n- test\nend"),
            array("blubber\n- -- bla\r\n- - test\rend", "blubber\n-- bla\r\n- test\rend"),
        );
    }

    /**
     * @dataProvider dataUnescapeGood
     */
    public function testDashUnescape($escaped, $unescaped) {
        $this->assertEquals($unescaped, OpenPGP::dashed_unescape($escaped));
    }

    /**
     * @dataProvider dataUnescapeGood
     */
    public function testDashEscape($escaped, $unescaped) {
        $this->assertEquals($escaped, OpenPGP::dashed_escape($unescaped));
    }

    public function testParseSignature() {
        $message = <<<EOM
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

Hello world
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.0.21 (MingW32)

iQIcBAEBAgAGBQJVBUjGAAoJEGO/bjERHYl/xQEQAKjFbMJvI8n/gJHaxCvElSf4
enu5s7c5hQoX3W2eMcyTQ9HdK2nbQWAzIlzIY+fVF13WrgYDGfg4qt4HVspLR++d
Q7GTvXSB9uAiXLQ3HnvUs09fpgK1M2qxyz6glLAeTceVzrJJXUgSmvF/Xq17TxS2
TZnWRuM0cdQqjfBADnjAKfliqD5n8tmkNh6p8EafL4iJUu6BZBRe7gRbGIt584BN
VclzvP7lvnlPs9+Cj1NtE41L8bsnctb0rlCZ7Wxo2psTQvpU8IVLmtD0PaysGY0H
uwEE0TFWSyrTx2xPHMS+sg/Er7DmBhRJ7XLhxBFXG6BLWn8iE3T5OGPuLP2keReb
4J/oCY5uoLNEp9f8KvFV/FW31nM+mCPxljbdFlJsZIL19z23JMbXmymoCo4BL16c
sJkhPSPq7lIcAuud/8MamZ+gF6ObqWYEPYGpCjDTc5ElNvINKeVV5uh4a+oXJNEu
G9z5iPyL18So0FA2U8iulAHVu+t2x2o5HwhyKDb0VRe72IjdyGs0p5OjyhhXtfCl
hYM6gexkEsbTK4pBmCqsOK7L8QsFAc2U+EK69eT/eV0WgeBpqZUYFrR9J3h40CcC
j48Fr+SwbyamjkYbw1BxlxAkmyRzvg1qBZtOMiFZOLUIDIsfNfg2kbw2ixUCfwh8
VyE/azrXzGn3A3eYAUTB
=GlK+
-----END PGP SIGNATURE-----
EOM;
        $keyASCII = file_get_contents(__DIR__ . '/data/stefan-test.asc');
        $pubkey = OpenPGP_Message::parse(OpenPGP::unarmor($keyASCII, 'PGP PUBLIC KEY BLOCK'));

        $m = OpenPGP::cleartext_signature_parse($message);

        /* Create a verifier for the key */
        $verify = new OpenPGP_Crypt_RSA($pubkey);

        /* Dump verification information to STDOUT */
        var_dump($verify->verify($m));

    }
}
