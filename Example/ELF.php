<?php
require('../vendor/autoload.php');

use AnalyzesExecuteFileFormat\ExecuteFormat\ELF\Manager;

echo '<xmp>';
try
{
    $executeObject = new Manager(fopen('perform.elf', 'r'));
    $analyze = $executeObject->getObjectFromBitMode();

    $elfHeader = $analyze->getElfHeader();

    print_r($elfHeader);
}
catch (Exception $e)
{
    echo $e->getMessage();
}
echo '</xmp>';
?>
