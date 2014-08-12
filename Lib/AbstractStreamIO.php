<?php
namespace PHPSecurityUploader\Lib;

abstract class AbstractStreamIO
{
    protected $_analysis = null;

    protected function __construct($analysis)
    {
        $this->_analysis = $analysis;
    }

    protected function __destruct()
    {
        $this->_close();
        unset($this->_analysis);
    }

    abstract protected _close();

    abstract public read($length, $offset = 0, $whence = SEEK_CUR)
    abstract public write($buffer, $offset = 0, $whence = SEEK_CUR)
}
?>
