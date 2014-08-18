<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

use AnalyzesExecuteFileFormat\Lib,
    AnalyzesExecuteFileFormat\ExecuteFormat;

class Bit32 extends AbstractExecuteFormat
{
    public function __construct(AbstractStreamIO &$streamio)
    {
        // not supported PE 32bit mode
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        parent::__construct($streamio);
    }

    public function __destruct()
    {
        parent::__destruct();
    }

    protected function getImageDosHeader()
    {
        // $this->_streamio;
    }
}
?>
