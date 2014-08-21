<?php
require('../Core.php');

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\FileIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\PE\Bit32;
use AnalyzesExecuteFileFormat\ExecuteFormat\PE\Bit64;

echo '<xmp>';
try
{
    $pe = new Bit32(new FileIO(fopen('procexp.exe', 'r')));

    $dosHeader = $pe->getImageDosHeader();
    $ntHeader = $pe->getImageNtHeaders($dosHeader);
    $sectionHeader = $pe->getImageSectionHeader($ntHeader);
    $importDescriptorArray = $pe->getImageImportDescriptors($ntHeader, $sectionHeader);
    $dllnameArray = $pe->getListOfImportDLL($importDescriptorArray);
    $funcionArray = $pe->getListOfImportFunction($importDescriptorArray);

    echo 'GetProcAddress(kernel32.FormatMessageA) = ' . $pe->getProcAddress('kernel32.dll', 'FormatMessageA') . "\n";

    //print_r($dosHeader);
    //print_r($ntHeader);
    //print_r($sectionHeader);
    //print_r($importDescriptorArray);
    print_r($dllnameArray);
    print_r($funcionArray);
}
catch (Exception $e)
{
    echo $e->getMessage();
}
echo '</xmp>';
?>
