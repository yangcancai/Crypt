<?php
/**
 * Created by IntelliJ IDEA.
 * User: master
 * Date: 6/18/16
 * Time: 4:39 PM
 * To change this template use File | Settings | File Templates.
 */
namespace YsTransferEncrypt;
require_once("RSAHelper.php");
require_once("AESHelper.php");
assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_QUIET_EVAL, 1);
// Create a handler function
function my_assert_handler($file, $line, $code, $desc = null)
{
    echo "Assertion failed at $file:$line: $code";
    if ($desc) {
        echo ": $desc";
    }
    echo "\n";
}
assert_options(ASSERT_CALLBACK, 'my_assert_handler');
final class EncryptType
{
    const IsAES = 1;
    const IsRSA = 2;
    const NON = 3;
}
class CryptHelper {
    // base64 transfer to base64url
   public static  function  base642base64url($data) {
        return rtrim(strtr($data, '+/', '-_'), '=');
    }
    // base64url transfer to base64
    public  static function  base64url2base64($data) {
        return str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT);
    }
    public  static  function SHA1Sign($msign,$timestamp,$token)
    {
         return strtoupper(sha1("msign=".$msign."&timestamp=".$timestamp."&token=".$token));
    }
    public static function  MD5Sign($key,$msg)
    {
       // echo "key==".$key."<br/>msg==".$msg."<br/>";
        return strtoupper(md5("aes_key=".$key."&compress=".$msg));
    }
    // 解码
     public static function Decode($msg,$token,$key)
     {
          try{
              $key_val = explode("&",$msg);
              $dictKeyVal = array();
              foreach($key_val as $key1=>$val)
              {
                     $s = explode("=",$val);
                    $dictKeyVal[$s[0]] = $s[1];
              }
              $sign = CryptHelper::SHA1Sign($dictKeyVal["msign"],$dictKeyVal["timestamp"],$token);
              $msign = CryptHelper::MD5Sign($dictKeyVal["encrypt"]=="IsRSA"?$token:$key,
                  $dictKeyVal["compress"]);
            //  echo $token;
             // echo "tt".$msign==$dictKeyVal["msign"];
              if ($sign==$dictKeyVal["sign"] && $msign==$dictKeyVal["msign"])
              {
                  $decode_msg = $dictKeyVal["compress"];
                  // aes encrypt
                  if ($dictKeyVal["encrypt"] == "IsAES") {
                     $decode_msg = decrypt_entry(CryptHelper::base64url2base64($dictKeyVal["compress"]),
                         $key,$key);
                  }
                  else if ($dictKeyVal["encrypt"]=="IsRSA")
                  {
                     $decode_msg = RSAHelper::RSADecrypt(CryptHelper::base64url2base64($dictKeyVal['compress']));
                  }
                  return $decode_msg;
              }
              else
              {
                  return null;
              }
          }catch (\Exception $e)
         {
             return null;
         }
     }
    // 编码
    public static function Encode($msg, $token, $key, $crypttype, $id)
    {
        try{
            $encode_msg = $msg;
            if ($crypttype==EncryptType::IsAES)
            {
                $encode_msg = CryptHelper::base642base64url(encrypt_entry($msg,$key,$key));
            }
            else if ($crypttype==EncryptType::IsRSA)
            {
               $encode_msg = CryptHelper::base642base64url(RSAHelper::RSAEncrypt($msg));
            }
            $timestamp = time();
            $msign = CryptHelper::MD5Sign($crypttype==EncryptType::IsRSA?$token:$key,$encode_msg);
            $sign = CryptHelper::SHA1Sign($msign,$timestamp,$token);
            return          "compress=".$encode_msg.
            "&id=".$id."&sign=".$sign."&timestamp="
            .$timestamp."&msign=".$msign."&encrypt="
            .(EncryptType::IsRSA==$crypttype?"IsRSA":
                (EncryptType::IsAES==$crypttype?"IsAES":"NON"));
        }catch (\Exception $e)
        {
            return null;
        }
    }
    public  static function GetOpensslPubKey()
    {
       return RSAHelper::GetPubKeyStr();
    }
    public static function Test()
    {
        $msg = "72fa43c4d76bb2cced0853959d8864cc72fa43c4d76bb";
        $token = "SbHtRC2GTvaldiNJ";
        $key = "SbHtRC2GTvaldiNJ";
        $encode_msg = CryptHelper::Encode($msg, $token, $key, EncryptType::NON, "0");
        $decode_msg = CryptHelper::Decode($encode_msg, $token, $key);
        assert($msg == $decode_msg,"encode_msg not eq decode_msg");

        $encode_msg = CryptHelper::Encode($msg, $token, $key, EncryptType::IsAES, "0");
        $decode_msg = CryptHelper::Decode($encode_msg, $token, $key);
        assert($msg == $decode_msg,"aes encrypt encode_msg not eq decode_msg");

        $encode_msg = CryptHelper::Encode($msg, RSAHelper::GetPubKeyStr(), RSAHelper::GetPubKeyStr(), EncryptType::IsRSA, "0");
        $decode_msg = CryptHelper::Decode($encode_msg, RSAHelper::GetPubKeyStr(), "");
        assert($msg == $decode_msg,"rsa encrypt encode_msg not eq decode_msg");
    }
}
//CryptHelper::Test();
//exit();
//exit(CryptHelper::MD5Sign(RSAHelper::GetPubKeyStr(),
  //  "RB7ixTXkH0dE5c2ECNA04b6E4zQgbpg
//  -eUJCn7aMLmrfA76VTT10In1HKIygVFX4rL98jFn481NsTND8E777V4EGz1mCIaZfZdy2Rp91Jq5NI4f8
//-nAazNxNi6uJ_TfY4xiYV3qx7lLx_UxaQg_OPf61tjCP7gKQ0efoViB9P_E"));
$token = "SbHtRC2GTvaldiNJ";
$key = "SbHtRC2GTvaldiNJ";
$token = $token;
$key = $key;
$req = CryptHelper::Decode($_SERVER["QUERY_STRING"],$token,$key);
//exit($req);
header('Content-type: application/json');
$t = $_GET['encrypt']=="IsRSA"?EncryptType::IsRSA:($_GET['encrypt']=="IsAES"?EncryptType::IsAES:EncryptType::NON);
//echo $token;
$arr["r"] = CryptHelper::Encode($req,$token, $key,$t,$_GET['id']);
$decode_msg = CryptHelper::Decode($arr["r"],$token,$key);
exit(json_encode($arr));
