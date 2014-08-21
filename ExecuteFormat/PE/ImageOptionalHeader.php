<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageOptionalHeader
{
    const IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

    // define of subsystem type
    const SUBSYSTEM_NATIVE = 1;
    const SUBSYSTEM_WINDOWS_GUI = 2;
    const SUBSYSTEM_WINDOWS_CUI = 3;

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
}
?>
