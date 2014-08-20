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
    $sectionHeader = $pe->getImageSectionHeader($ntHeader);

    print_r($dosHeader);
    print_r($ntHeader);
    print_r($sectionHeader);
}
catch (Exception $e)
{
    echo $e->getMessage();
}
?>
