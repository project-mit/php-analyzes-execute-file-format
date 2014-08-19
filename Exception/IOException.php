<?php
namespace AnalyzesExecuteFileFormat\Exception;

use Exception,
    RuntimeException;

class IOException extends RuntimeException
{
    public function __construct($message, Exception $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
?>
