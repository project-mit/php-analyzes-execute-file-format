<?php
namespace PHPSecurityUploader\Lib\StreamIO;

use PHPSecurityUploader\Lib;
use PHPSecurityUploader\Exception;

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

    protected function _close()
    {
    }

    public function read($length, $offset = 0, $whence = SEEK_CUR)
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);
    }

    public function write($buffer, $offset = 0, $whence = SEEK_CUR)
    {
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);
    }
}
?>
