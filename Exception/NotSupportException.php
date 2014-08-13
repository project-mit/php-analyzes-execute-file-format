<?php
namespace PHPSecurityUploader\Exception;

class NotSupportException extends Exception
{
    public function __construct($method, Exception $previous = null)
    {
        parent::__construct('The method ' . $method . ' is not supported by class.', 0, $previous);
    }
}
?>
