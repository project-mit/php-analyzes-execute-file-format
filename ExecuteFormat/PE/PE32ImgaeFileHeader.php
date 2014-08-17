<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE\32;

class ImageFileHeader
{
    public $machine;
    public $numberOfSections;
    public $timeDateStamp;
    public $pointerToSymbolTable;
    public $numberOfSymbols;
    public $sizeOfOptionalHeader;
    public $characteristics;
}
?>
