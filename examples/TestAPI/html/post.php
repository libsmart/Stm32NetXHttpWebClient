<?php
ob_start();

$str = file_get_contents("php://input");
file_put_contents("out.txt", $str);

$data = [
    'successful' => true
];

echo json_encode($data, JSON_PRETTY_PRINT|JSON_FORCE_OBJECT);

header('Content-Length: '.ob_get_length());
ob_end_flush();
