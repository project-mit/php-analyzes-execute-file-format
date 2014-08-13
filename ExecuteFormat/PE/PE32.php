<?php
namespace PHPSecurityUploader\ExecuteFormat\PE;

use PHPSecurityUploader\Lib;
use PHPSecurityUploader\ExecuteFormat;

class PE32 extends AbstractExecuteFormat
{
    public function __construct(AbstractStreamIO $streamio)
    {
        // not supported PE 32bit mode
        throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        parent::__construct($streamio);
    }

    public function __destruct()
    {
        parent::__destruct();
    }
}
?>
