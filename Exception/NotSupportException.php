<?php
namespace AnalyzesExecuteFileFormat\Exception;

use Exception,
    RuntimeException;

class NotSupportException extends RuntimeException
{
    public function __construct($method, Exception $previous = null)
    {
        parent::__construct('The method ' . $method . ' is not supported by class.', 0, $previous);
    }
}
?>
