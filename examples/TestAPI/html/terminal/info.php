<?php

ob_start();

$data = [
    'successful' => true,
    'message' => '',
    'resultObject' => [
        'info' => [
            'chronoVersion' => 2,
            'serverTime' => (new DateTime('now', new DateTimeZone('Europe/Zurich')))
                ->format("Y-m-d\TH:i:s"),
        ],
        'culture' => 'de-CH',
    ],
];


echo json_encode($data, JSON_PRETTY_PRINT | JSON_FORCE_OBJECT);

header('Content-Type: application/json; charset=utf-8');
header('Content-Length: ' . ob_get_length());
ob_end_flush();
