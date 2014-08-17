<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat;

use AnalyzesExecuteFileFormat\Lib;

class AbstractExecuteFormat
{
    protected $_streamio = null;

    protected function __construct(AbstractStreamIO $streamio)
    {
        if (is_object($streamio) === false)
            throw new BadMethodCallException('The parameter is not objects of class.');

        $this->_streamio = $streamio;
    }

    protected function __destruct()
    {
        unset($this->_streamio);
    }
}
?>
