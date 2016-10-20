<?php
require_once 'xmlseclibs/xmlseclibs.php';
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

// certificate file locations
$public_cert_path = 'certs/uidai_auth_stage.cer';
$p12_file = 'certs/Staging_Signature_PrivateKey.p12';

// set variables
$aadhaar_no = '999999990019';
$api_version = "1.6";
$asa_licence_key = "MH4hSkrev2h_Feu0lBRC8NI-iqzT299_qPSSstOFbNFTwWrie29ThDo";
$lk = "MBFWjkJHNF-fLidl8oOHtUwgL5p1ZjDbWrqsMEVEJLVEDpnlNj_CZTg";
$ac = "public";
$sa = "public";
$tid = "public";
$private_key_path = '/Users/fryday/Sites/aadhaar_php/certs/sig.key.pem';
$private_cert_path = '/Users/fryday/Sites/elixir/aadhaar/certs/sig.crt.pem';
$public_cert_path = '/Users/fryday/Sites/aadhaar_php/certs/uidai_auth_stage.cer';
$txn = "AuthDemoClient:public:".date("Ymdhms");
$ts = date('Y-m-d').'T'.date('H:i:s');

// PID Block
$pid_block='<?xml version="1.0"?><ns2:Pid ts="2016-10-20T04:55:53" xmlns:ns2="http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0"><ns2:Demo><ns2:Pi ms="E" mv="100" name="Shivshankar Choudhury"/></ns2:Demo></ns2:Pid>';

// generate aes-256 session key
$session_key = openssl_random_pseudo_bytes(32);


// generate auth xml
$auth_xml = '<?xml version="1.0"?><Auth ac="'.$ac.'" lk="'.$lk.'" sa="'.$sa.'" tid="'.$sa.'" txn="'.$txn.'" uid="'.$aadhaar_no.'" ver="'.$api_version.'" xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/1.0" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><Uses bio="n" otp="n" pa="n" pfa="n" pi="y" pin="n"/><Meta fdc="NA" idc="NA" lot="P" lov="560094" pip="NA" udc="1122"/><Skey ci="'.public_key_validity().'">'.encrypt_session_key($session_key).'</Skey><Data type="X">'.encrypt_pid($pid_block, $session_key).'</Data><Hmac>'.calculate_hmac($pid_block, $session_key).'</Hmac></Auth>';

// echo $auth_xml;
// die();

// xmldsig the auth xml
$doc = new DOMDocument();
$doc->loadXML($auth_xml);
$objDSig = new XMLSecurityDSig();
$objDSig->setCanonicalMethod(XMLSecurityDSig::C14N);
$objDSig->addReference(
    $doc,
    XMLSecurityDSig::SHA256,
    array(
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#'
    ),
    array('force_uri' => true)
);
$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type'=>'private'));
openssl_pkcs12_read(file_get_contents($p12_file), $key, "public");
$objKey->loadKey($key["pkey"]);
$objDSig->add509Cert($key["cert"]);
$objDSig->sign($objKey, $doc->documentElement);


// make a request to uidai
$ch = curl_init("http://auth.uidai.gov.in/$api_version/public/".$aadhaar_no[0]."/".$aadhaar_no[0]."/$asa_licence_key");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $doc->saveXML());
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
  "Accept: application/xml",
  "Content-Type: application/xml"
));
echo "\nRequest XML\n";
echo $doc->saveXML();
echo "\n\n";
echo "Response from UIDAI\n";
echo htmlspecialchars_decode(curl_exec($ch));



function encrypt_pid($pid_block, $session_key)
{
    return encrypt_using_session_key($pid_block, $session_key);
}

function encrypt_using_session_key($data, $session_key)
{
    $blockSize = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
    $pad = $blockSize - (strlen($data) % $blockSize);
    return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $session_key, $data . str_repeat(chr($pad), $pad), MCRYPT_MODE_ECB));
}

function calculate_hmac($data, $session_key)
{
    return encrypt_using_session_key(hash('sha256', $data, true), $session_key);
}

function public_key_validity()
{
    global $public_cert_path;
    $certinfo = openssl_x509_parse(file_get_contents($public_cert_path));
    return date('Ymd', $certinfo['validTo_time_t']);
}

function encrypt_session_key($session_key)
{
    global $public_cert_path;
    $pub_key = openssl_pkey_get_public(file_get_contents($public_cert_path));
    $keyData = openssl_pkey_get_details($pub_key);
    openssl_public_encrypt($session_key, $encrypted_session_key, $keyData['key'], OPENSSL_PKCS1_PADDING);
    return base64_encode($encrypted_session_key);
}
