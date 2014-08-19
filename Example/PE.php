<?php
require('../Core.php');

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\FileIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\PE\Bit32;

try
{
    $pe = new Bit32(new FileIO(fopen('procexp.exe', 'r')));
    print_r($pe->getImageDosHeader());
}
catch (NotSupportException $e)
{
    echo $e->getMessage();
}
?>
