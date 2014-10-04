<?php
require('../vendor/autoload.php');

use AnalyzesExecuteFileFormat\ExecuteFormat\PE\Manager;

echo '<xmp>';
try
{
    $executeObject = new Manager(fopen('procexp.exe', 'r'));
    $analyze = $executeObject->getObjectFromBitMode();

    $dosHeader = $analyze->getImageDosHeader();
    $ntHeader = $analyze->getImageNtHeaders($dosHeader);
    $sectionHeader = $analyze->getImageSectionHeader($ntHeader);

    // export
    $exportDescriptor = $analyze->getImageExportDescriptor($ntHeader, $sectionHeader);
    $exportDllname = $analyze->getListOfExportFileName($exportDescriptor);
    $exportFuncionArray = $analyze->getListOfExportFunction($exportDescriptor);

    var_dump($exportDllname);
    print_r($exportFuncionArray);

    // import
    $importDescriptorArray = $analyze->getImageImportDescriptors($ntHeader, $sectionHeader);
    $importDllnameArray = $analyze->getListOfImportDLL($importDescriptorArray);
    $importFuncionArray = $analyze->getListOfImportFunction($importDescriptorArray);

    echo 'GetProcAddress(kernel32.FormatMessageA) = ' . $analyze->getProcAddress('kernel32.dll', 'FormatMessageA') . "\n";

    print_r($importDllnameArray);
    print_r($importFuncionArray);
}
catch (Exception $e)
{
    echo $e->getMessage();
}
echo '</xmp>';
?>
