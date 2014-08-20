<?php
namespace AnalyzesExecuteFileFormat\Lib\StreamIO;

use AnalyzesExecuteFileFormat\Exception\InvalidException,
    AnalyzesExecuteFileFormat\Exception\NotSupportException;

class BinaryIO extends AbstractStreamIO
{
    public function __construct($buffer)
    {
        // if $buffer of parameter is not string, throw exception!!
        if (is_string($buffer) === false)
            throw new InvalidException('The parameter is not string resource.');

        parent::__construct($buffer);
    }

    public function __destruct()
    {
        parent::__destruct();
    }

    public function read($length, $offset = -1, $whence = SEEK_SET)
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        return $this;
    }

    public function write(string $buffer, $offset = -1, $whence = SEEK_SET)
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        return $this;
    }

    public function toString()
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);
    }

    public function toInteger()
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);
    }

    public function toIntArray($valueSize = 1)
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);
    }
}
?>
