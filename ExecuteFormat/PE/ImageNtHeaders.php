<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageNtHeaders
{
    public $signature;

    // IMAGE_FILE_HEADER
    public $fileheader = null;

    // IMAGE_OPTIONAL_HEADER
    public $optionalheader = null;

    public function __construct()
    {
        $this->fileheader = new ImageFileHeader();
        $this->optionalheader = new ImageOptionalHeader();
    }

    public function __destruct()
    {
        unset($this->fileheader);
        unset($this->optionalheader);
    }
}
?>
