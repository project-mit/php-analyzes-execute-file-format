<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

use AnalyzesExecuteFileFormat\Lib,
    AnalyzesExecuteFileFormat\ExecuteFormat;

class PE64 extends AbstractExecuteFormat
{
    public function __construct(AbstractStreamIO $streamio)
    {
        // not supported PE 64bit mode
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        parent::__construct($streamio);
    }

    public function __destruct()
    {
        parent::__destruct();
    }
}
?>
