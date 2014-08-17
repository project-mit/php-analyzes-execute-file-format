<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE\32;

class ImageNtHeaders
{
    const IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

    public $signature;

    // IMAGE_FILE_HEADER
    public $machine;
    public $numberOfSections;
    public $timeDateStamp;
    public $pointerToSymbolTable;
    public $numberOfSymbols;
    public $sizeOfOptionalHeader;
    public $characteristics;

    // IMAGE_OPTIONAL_HEADER
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
    public $dataDirectory = array_fill(0, self::IMAGE_NUMBEROF_DIRECTORY_ENTRIES, new ImageDataDirectory());
}
?>
