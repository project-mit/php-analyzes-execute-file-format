<?php
require('../Core.php');

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\FileIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\PE\ExecuteFormat;

echo '<xmp>';
try
{
    $executeObject = new ExecuteFormat(new FileIO(fopen('procexp.exe', 'r')));
    $pe = $executeObject->getObjectFromBitMode();

    $dosHeader = $pe->getImageDosHeader();
    $ntHeader = $pe->getImageNtHeaders($dosHeader);
    $sectionHeader = $pe->getImageSectionHeader($ntHeader);

    // export
    $exportDescriptor = $pe->getImageExportDescriptor($ntHeader, $sectionHeader);
    $exportDllname = $pe->getListOfExportFileName($exportDescriptor);
    $exportFuncionArray = $pe->getListOfExportFunction($exportDescriptor);

    var_dump($exportDllname);
    print_r($exportFuncionArray);

    // import
    $importDescriptorArray = $pe->getImageImportDescriptors($ntHeader, $sectionHeader);
    $importDllnameArray = $pe->getListOfImportDLL($importDescriptorArray);
    $importFuncionArray = $pe->getListOfImportFunction($importDescriptorArray);

    echo 'GetProcAddress(kernel32.FormatMessageA) = ' . $pe->getProcAddress('kernel32.dll', 'FormatMessageA') . "\n";

    print_r($importDllnameArray);
    print_r($importFuncionArray);
}
catch (Exception $e)
{
    echo $e->getMessage();
}
echo '</xmp>';
?>
