<?php
ob_start();

echo (new DateTime())->format("Y-m-d H:i:s.v");
echo PHP_EOL;

header('Content-Length: '.ob_get_length());
ob_end_flush();
