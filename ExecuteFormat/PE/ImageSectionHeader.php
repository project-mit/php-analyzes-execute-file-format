<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageSectionHeader
{
    const IMAGE_SIZEOF_SHORT_NAME = 8;

    public $name = null;
    public $misc = [
        'physicalAddress' => 0,
        'virtualSize' => 0
    ];
    public $virtualAddress;
    public $sizeOfRawData;
    public $pointerToRawData;
    public $pointerToLineNumbers;
    public $numberOfRelocations;
    public $numberOfLineNumbers;
    public $ccharacteristics;

    public function __construct()
    {
        $this->name = array_fill(0, self::IMAGE_SIZEOF_SHORT_NAME, '');
    }

    public function __destruct()
    {
        foreach ($this->name as $key => $value)
        {
            unset($this->name[$key]);
        }
        unset($this->name);
    }
}
?>
