<?php
/**
 * Created by IntelliJ IDEA.
 * User: master
 * Date: 6/17/16
 * Time: 10:54 AM
 * To change this template use File | Settings | File Templates.
 */
namespace YsTransferEncrypt;
class RSAHelper
{
    private static  $privateKeyFilePath = '../rsa_key/rsa_private_key.pem';
    private static  $publicKeyFilePath = '../rsa_key/rsa_public_key.pem';
    private static  $publickey;
    private static  $privateKey;
    private static $pubkey_str = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAnX5k3H98bjOqOfDJLJWkF+VR
HxtUkzlOGZQYUiE4luqx0sr0kuEE5bUOXcoCm+3mVNeFxLJ08dShUQF6e4Xuplvg
k/RfRfRgpPjVd6WhRNnNKvPsBP2D4/tG+Qd1SSnzd8i3xpuAZl/u8dn3Z0Aqtz4W
+dTuiKpCRTuJXwfNBQIDAQAB
-----END PUBLIC KEY-----
";
    private static $privatekey_str = "-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDAnX5k3H98bjOqOfDJLJWkF+VRHxtUkzlOGZQYUiE4luqx0sr0
kuEE5bUOXcoCm+3mVNeFxLJ08dShUQF6e4Xuplvgk/RfRfRgpPjVd6WhRNnNKvPs
BP2D4/tG+Qd1SSnzd8i3xpuAZl/u8dn3Z0Aqtz4W+dTuiKpCRTuJXwfNBQIDAQAB
AoGAbUOqZJr0suhs5H7TybtB9AEeM+N6hIKzuksmSJmmgMyTvGZAfXcosLeB+vFX
XB2KWeP9EsQfG9nnbc9fEFUsBtYcINeJqNi7KF3rIXzijC5yBUHmD0yMIcQLpW9f
WiPB1jISpyurxbHj1/qcdi9s1dRAzh81ZwR+6pgOYnO3b40CQQDo/w8ntXSpdc0j
/1Bi/8OgK55XYgLteaWhMe6RyV66wZmegAIpT6iowNQzawoVJPCPGEl/db5LWSXO
Ix7V5IPzAkEA06HPGsR14KUaQUalml+UhWjntyuFhDUR3ry/YEZ/zsVhf+z8jTJ+
MN5Pz5xcs8NeAvH7q0eBiTw2LXo/pi1BJwJBAJ+U6nVhFAlpFNs96HoWAY/3sBjb
mXO7aNUSFPunN4mkRipINLLEy5jhkbWx75Lx3Q21LcnuBCspYPpiFaGcRT8CQQCh
NHMuv5HPAdSi/m5szfuzN7qxsywsDcTD9uCMNIdseLuRF3M1Fs466UzAJyoSIHI/
KhZ7XKeWYtAeCi3rpjMnAkEAmC2tZP5mLMgCmZdsBJPNdG0XXYMSMwmIvXsKJU4F
6t4x1tuY+8e9n+CG7Mx3KneYpLOmKHyp5S4H4jE38xIOYg==
-----END RSA PRIVATE KEY-----
";
    public static  function load()
    {
        if (isset(RSAHelper::$publickey)==false)
        {
            $data = file_get_contents(RSAHelper::$privateKeyFilePath);
            RSAHelper::$privatekey_str = $data==false?RSAHelper::$privatekey_str:$data;
            $data =  file_get_contents(RSAHelper::$publicKeyFilePath);
            RSAHelper::$pubkey_str = $data==false?RSAHelper::$pubkey_str:$data;
            RSAHelper::$privateKey = openssl_pkey_get_private(RSAHelper::$privatekey_str);
            RSAHelper::$publickey = openssl_pkey_get_public(RSAHelper::$pubkey_str);
        }
    }

    public static  function RSAEncrypt($msg)
    {
        RSAHelper::load();
        $encryptData = '';
        openssl_public_encrypt($msg, $encryptData, RSAHelper::$publickey);
        return base64_encode($encryptData);
    }

    public static function  RSADecrypt($encryptData)
    {
        RSAHelper::load();
        $decryptData = '';
        openssl_private_decrypt(base64_decode($encryptData), $decryptData, RSAHelper::$privateKey);
        return $decryptData;
    }
    public  static function GetPubKeyStr()
    {
        RSAHelper::load();
        return RSAHelper::$pubkey_str;
    }
    // base64 transfer to base64url
    public static  function  base642base64url($data) {
        return rtrim(strtr($data, '+/', '-_'), '=');
    }
    // base64url transfer to base64
    public  static function  base64url2base64($data) {
        return str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT);
    }
}
////  $h = new RSAHelper();
//  $plaintext = "72fa43c4d76bb2cced0853959d8864cc72fa43c4d76bb111111111111111111111111111";
// $encodeData = RSAHelper::RSAEncrypt($plaintext);
 $encodeData = RSAHelper::base64url2base64("FKq5vmiPvWJJh7oIi-RuxohsaPXtGT1TlLFdMIGTNEs75pvNbws3YvFD7kQt-b6y83qsOu5jrqraXqGFz-WU_Ai2PrED_S0FDvyRAZQbBpBmeZ8Pkx1S6IL3z_usj82AysZ3Wgqmg8sMEuX1LrH33LxnZnkx4PuFdR7OLMr-Hig");
 $decodeData = RSAHelper::RSADecrypt($encodeData);
//exit($decodeData);
// echo $decodeData==$plaintext;
//exit(RSAHelper::GetPubKeyStr());
?>