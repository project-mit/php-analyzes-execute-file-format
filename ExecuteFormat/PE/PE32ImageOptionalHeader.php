<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE\32;

class ImageOptionalHeader
{
    const IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

    public $magic;
    public $majorLinkerVersion;
    public $minorLinkerVersion;
    public $sizeOfCode;
    public $sizeOfInitializedData;
    public $sizeOfUninitializedData;
    public $addressOfEntryPoint;
    public $baseOfCode;
    public $baseOfData;
    public $imageBase;
    public $sectionAlignment;
    public $fileAlignment;
    public $majorOperatingSystemVersion;
    public $minorOperatingSystemVersion;
    public $majorImageVersion;
    public $minorImageVersion;
    public $majorSubsystemVersion;
    public $minorSubsystemVersion;
    public $win32VersionValue;
    public $sizeOfImage;
    public $sizeOfHeaders;
    public $checksum;
    public $subsystem;
    public $dllCharacteristics;
    public $sizeOfStackReserve;
    public $sizeOfStackCommit;
    public $sizeOfHeapReserve;
    public $sizeOfHeapCommit;
    public $loaderFlags;
    public $numberOfRvaAndSizes;
    public $dataDirectory = null;

    public function __construct()
    {
        $this->dataDirectory = array_fill(0, self::IMAGE_NUMBEROF_DIRECTORY_ENTRIES, new ImageDataDirectory());
    }

    public function __destruct()
    {
        foreach ($this->dataDirectory as $key => $value)
        {
            unset($this->dataDirectory[$key]);
        }
        unset($this->dataDirectory);
    }
}
?>