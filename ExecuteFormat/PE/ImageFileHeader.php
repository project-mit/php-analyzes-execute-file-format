<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageFileHeader
{
    const MACHINE_UNKNOWN = 0;
    const MACHINE_I386 = 0x014c;
    const MACHINE_R3000 = 0x0162;
    const MACHINE_R4000 = 0x0166;
    const MACHINE_R10000 = 0x0168;
    const MACHINE_WCEMIPSV2 = 0x0169;
    const MACHINE_ALPHA = 0x0184;
    const MACHINE_SH3 = 0x01a2;
    const MACHINE_SH3DSP = 0x01a3;
    const MACHINE_SH3E = 0x01a4;
    const MACHINE_SH4 = 0x01a6;
    const MACHINE_SH5 = 0x01a8;
    const MACHINE_ARM = 0x01c0;
    const MACHINE_THUMB = 0x01c2;
    const MACHINE_ARMNT = 0x01c4;
    const MACHINE_AM33 = 0x01d3;
    const MACHINE_POWERPC = 0x01f0;
    const MACHINE_POWERPCFP = 0x01f1;
    const MACHINE_IA64 = 0x0200;
    const MACHINE_MIPS16 = 0x0266;
    const MACHINE_ALPHA64 = 0x0284;
    const MACHINE_MIPSFPU = 0x0366;
    const MACHINE_MIPSFPU16 = 0x0466;
    const MACHINE_AXP64 = MACHINE_ALPHA64;
    const MACHINE_TRICORE = 0x520;
    const MACHINE_CEF = 0x0cef;
    const MACHINE_EBC = 0x0ebc;
    const MACHINE_AMD64 = 0x8664;
    const MACHINE_M32R = 0x9041;
    const MACHINE_CEE = 0xc0ee;

    const FILE_RELOCS_STRIPPED = 0x0001;
    const FILE_EXECUTEABLE_IMAGE = 0x0002;
    const FILE_LINE_NUMS_STRIPPED = 0x0004;
    const FILE_LOCAL_SYMS_STRIPPED = 0x0008;
    const FILE_AGGRESIVE_WS_TRIM = 0x0010;
    const FILE_LARGE_ADDRESS_AWARE = 0x0020;
    const FILE_BYTES_REVERSED_LO = 0x0080;
    const FILE_32BIT_MACHINE = 0x0100;
    const FILE_DEBUG_STRIPPED = 0x0200;
    const FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400;
    const FILE_NET_RUN_FROM_SWAP = 0x0800;
    const FILE_SYSTEM = 0x1000;
    const FILE_DLL = 0x2000;
    const FILE_UP_SYSTEM_ONLY = 0x4000;
    const FILE_BYTES_RESERVED_HI = 0x8000;

    public $machine;
    public $numberOfSections;
    public $timeDateStamp;
    public $pointerToSymbolTable;
    public $numberOfSymbols;
    public $sizeOfOptionalHeader;
    public $characteristics;
}
?>
