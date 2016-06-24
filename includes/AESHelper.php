<?php
/**
 * AES加密、解密类
 */
class AESHelper{
    public function __construct(){   }
    /// $iv = mcrypt_create_iv(mcrypt_get_iv_size($enc, $mode), MCRYPT_DEV_URANDOM);
    // $enc = MCRYPT_RIJNDAEL_128;
    // $mode = MCRYPT_MODE_CBC;
    public  static function  AESEncode($enc,$mode,$key,$iv,$str)
    {
        $str = AESHelper::addPkcs7Padding($str);
        if ($iv!='')
        {
            return base64_encode(mcrypt_encrypt($enc, $key, $str, $mode, $iv));
        }
        else{
            return base64_encode(mcrypt_encrypt($enc, $key, $str, $mode));
        }
    }
    public  static function  AESDecode($enc,$mode,$key,$iv,$str)
    {
        $decode_msg = "";
        if ($iv=='')
            $decode_msg =  mcrypt_decrypt($enc, $key, base64_decode($str), $mode);
        else
            $decode_msg = mcrypt_decrypt($enc, $key, base64_decode($str), $mode,$iv);
        return AESHelper::stripPkcs7Padding($decode_msg);
    }
    /**
     * pkcs7补码
     *
     * @param string $string 明文
     * @param int $blocksize Blocksize , 以 byte 为单位
     *
     * @return String
     */
    private static  function addPkcs7Padding($string, $blocksize = 32) {
        $len = strlen($string); //取得字符串长度
        $pad = $blocksize - ($len % $blocksize); //取得补码的长度
        $string .= str_repeat(chr($pad), $pad); //用ASCII码为补码长度的字符， 补足最后一段
        return $string;
    }/**
 * 除去pkcs7 padding
 *
 * @param String 解密后的结果
 *
 * @return String
 */
    private static function stripPkcs7Padding($string){
        $slast = ord(substr($string, -1));
        $slastc = chr($slast);
        $pcheck = substr($string, -$slast);
        if(preg_match("/$slastc{".$slast."}/", $string)){
            $string = substr($string, 0, strlen($string)-$slast);
            return $string;
        } else {
            return false;
        }
    }
}
function decrypt_entry($str,$key="SbHtRC2GTvaldiNJ",$iv='')
{
    return trim(AESHelper::AESDecode(MCRYPT_RIJNDAEL_128,MCRYPT_MODE_CBC,$key,$iv,$str));
}
function encrypt_entry($str,$key="SbHtRC2GTvaldiNJ",$iv='')
{
    return AESHelper::AESEncode(MCRYPT_RIJNDAEL_128,MCRYPT_MODE_CBC,$key,$iv,$str);
}
//$str="72fa43c4d76bb2cced0853959d8864cc72fa43c4d76bb";
//$iv = "SbHtRC2GTvaldiNJ";
//$key = "SbHtRC2GTvaldiNJ";
//$encode_str = encrypt_entry($str,$key,$iv);
//$decode_str = decrypt_entry($encode_str,$key,$iv);
//echo $encode_str."<br/>".$decode_str;

//$enc = MCRYPT_RIJNDAEL_128;
//$mode = MCRYPT_MODE_CBC;
//$iv = mcrypt_create_iv(mcrypt_get_iv_size($enc, $mode), MCRYPT_DEV_URANDOM);
//$encode_str = mcrypt_encrypt($enc, $key, $str, $mode, $iv);
//$decode_str = mcrypt_decrypt($enc,$key, $encode_str, $mode, $iv);
//echo "<br/>".base64_encode($encode_str)."<br/>".$decode_str;

?>