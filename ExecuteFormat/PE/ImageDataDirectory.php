<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageDataDirectory
{
    const EXPORT_DIRECTORY = 0x0;
    const IMPORT_DIRECTORY = 0x1;
    const RESOURCE_DIRECTORY = 0x2;
    const EXCEPTION_DIRECTORY = 0x3;
    const SECURITY_DIRECTORY = 0x4;
    const BASERELOC_DIRECTORY = 0x5;
    const DEBUG_DIRECTORY = 0x6;
    const COPYRIGHT_DIRECTORY = 0x7;
    const GLOBALPTR_DIRECTORY = 0x8;
    const TLS_DIRECTORY = 0x9;
    const LOAD_CONFIG_DIRECTORY = 0xA;
    const BOUND_IMPORT_DIRECTORY = 0xB;
    const IAT_DIRECTORY = 0xC;
    const DELAY_IMPORT_DIRECTORY = 0xD;
    const COM_DESCRIPTOR_DIRECTORY = 0xE;
    const RESERVED_DIRECTORY = 0xF;

    public $virtualAddress;
    public $size;
}
?>
