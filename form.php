<?php

require_once 'includes/sqAES.php';
require_once 'includes/JCryption.php';

$postBefore = print_r($_POST, true);

JCryption::decrypt();

header('Content-type: text/plain');
echo "Original POST\n======================\n";
print_r($postBefore);
echo "jCryption example form\n======================\n";
print_r($_POST);
