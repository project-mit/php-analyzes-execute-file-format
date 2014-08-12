<?php
namespace PHPSecurityUploader;

use PHPSecurityUploader\Lib;

class AbstractExecuteFormat
{
    protected $_streamio = null;

    protected function __construct($streamio)
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
