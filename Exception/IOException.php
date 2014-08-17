<?php
namespace AnalyzesExecuteFileFormat\Exception;

class IOException extends Exception
{
    public function __construct($message, Exception $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
?>
