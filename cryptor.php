<?php

function my_encrypt($data, $passphrase) {
    $secret_key = hex2bin($passphrase);
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted_64 = openssl_encrypt($data, 'aes-256-cbc', $secret_key, 0, $iv);
    $iv_64 = base64_encode($iv);
    $json = new stdClass();
    $json->iv = $iv_64;
    $json->data = $encrypted_64;
    return base64_encode(json_encode($json));
}

function my_decrypt($data, $passphrase) {
    $secret_key = hex2bin($passphrase);
    $json = json_decode(base64_decode($data));
    $encrypted_64 = $json->{'data'};
    $iv = base64_decode($json->{'iv'});
    $data_encrypted = base64_decode($encrypted_64);
    $decrypted = openssl_decrypt($data_encrypted, 'aes-256-cbc', $secret_key, OPENSSL_RAW_DATA, $iv);
    return $decrypted;
}



$salt = '34172bac9b7f5b85b770343bcf0dc61cddfebd52440338b7f81fde32dd0b7ca5';


echo $test = my_encrypt("Hello this is test",$salt); echo "\n";
echo my_decrypt($test,$salt); echo "\n";
echo my_decrypt("eyJpdiI6ICI0L3hTVitXRlhnYmRrcXEzTXVVM1FRPT0iLCAiZGF0YSI6ICJMYnl0UlRTODJkSU1odDZNbEhnUHVnPT0ifQ==",$salt); echo "\n";

