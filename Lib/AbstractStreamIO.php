<?php
namespace AnalyzesExecuteFileFormat\Lib\StreamIO;

abstract class AbstractStreamIO
{
    protected $_analysis = null;

    protected function __construct($analysis)
    {
        $this->_analysis = $analysis;
    }

    protected function __destruct()
    {
        unset($this->_analysis);
    }

    abstract public function read($length, $offset = 0, $whence = SEEK_CUR);
    abstract public function write(string $buffer, $offset = 0, $whence = SEEK_CUR);

    abstract public function toString();
    abstract public function toInteger();
    abstract public function toIntArray($valueSize = 1);
}
?>
