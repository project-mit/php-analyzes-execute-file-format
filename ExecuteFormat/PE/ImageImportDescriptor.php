<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageImportDescriptor
{
    public $dummyUnionName = [
        'characteristics' => 0,
        'ordiginalFirstThunk' => 0
    ];
    public $timeDateStamp;
    public $forwarderChain;
    public $name;
    public $firstThunk;
}
?>
