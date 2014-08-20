<?php
require('../Core.php');

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\FileIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\PE\Bit32;

try
{
    $pe = new Bit32(new FileIO(fopen('procexp.exe', 'r')));

    $dosHeader = $pe->getImageDosHeader();
    $ntHeader = $pe->getImageNtHeaders($dosHeader);
    print_r($dosHeader);
    print_r($ntHeader);
}
catch (Exception $e)
{
    echo $e->getMessage();
}
?>
