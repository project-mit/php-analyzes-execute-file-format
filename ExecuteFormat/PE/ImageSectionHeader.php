<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageSectionHeader
{
    const IMAGE_SIZEOF_SECTION_HEADER = 40;
    const IMAGE_SIZEOF_SHORT_NAME = 8;

    const SCN_CNT_CODE = 0x00000020;
    const SCN_CNT_INITIALIZED_DATA = 0x00000040;
    const SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
    const SCN_CNT_EXECUTE = 0x20000000;
    const SCN_CNT_READ = 0x40000000;
    const SCN_CNT_WRITE = 0x80000000;

    public $name = null;
    public $misc = [
        'physicalAddress' => 0,
        'virtualSize' => 0
    ];
    public $virtualAddress;
    public $sizeOfRawData;
    public $pointerToRawData;
    public $pointerToRelocations;
    public $pointerToLineNumbers;
    public $numberOfRelocations;
    public $numberOfLineNumbers;
    public $ccharacteristics;
}
?>
