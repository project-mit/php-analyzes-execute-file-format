<?php
namespace AnalyzesExecuteFileFormat\Lib\StreamIO;

use AnalyzesExecuteFileFormat\Exception\InvalidException,
    AnalyzesExecuteFileFormat\Exception\IOException;

class FileIO extends AbstractStreamIO
{
    const LITTLE_ENDIAN = 0;
    const BIG_ENDIAN = 1;

    private $__data = '';
    private $__endian = 0;

    public function __construct($fileobject)
    {
        // if $fileobject of parameter is not resource, throw exception!!
        if (is_resource($fileobject) === false)
            throw new InvalidException('The parameter is not file resource.');

        parent::__construct($fileobject);
    }

    public function __destruct()
    {
        // if $fileobject is resource, file pointer close!!
        if (is_resource($this->_analysis) === true)
            fclose($this->_analysis);

        parent::__destruct();
    }

    public function setEndian($endian)
    {
        if (true === is_integer($endian))
        {
            $this->__endian = $endian;
            return $this;
        }
        return null;
    }

    public function read($length, $offset = -1, $whence = SEEK_SET)
    {
        // move to file pointer
        if ($offset !== -1) fseek($this->_analysis, $offset, $whence);

        // if file pointer is end of file?
        if (feof($this->_analysis) === true)
            throw new IOException('The position of this file pointer is end-of-file.');

        // read to data of file
        if ($length > 0)
        {
            if (($buffer = fread($this->_analysis, $length)) !== false)
                $this->__data = $buffer;
        }
        return $this;
    }

    public function write(string $buffer, $offset = -1, $whence = SEEK_SET)
    {
        // null buffer
        if ($buffer === null) return false;

        // move to file pointer
        if ($offset !== -1) fseek($this->_analysis, $offset, $whence);

        // write to data of buffer
        $writelength = 0;
        if (($writelength = fwrite($this->_analysis, $buffer)) === false)
            throw new IOException($writelength . ' bytes from ' . strlen($buffer) . ' bytes was written to successful.');

        return $writelength;
    }

    public function toString()
    {
        return $this->__data;
    }

    public function toInteger()
    {
        $binary = $this->__data;

        $binary = str_split($binary);
        $binary = array_map(
            function ($value)
            {
                return sprintf('%02x', ord($value));
            },
            $binary
        );

        if ($this->__endian === self::LITTLE_ENDIAN)
            $binary = array_reverse($binary);

        return hexdec(implode('', $binary));
    }

    public function toIntArray($valueSize = 1)
    {
        $binarys = str_split($this->__data, $valueSize);
        if ($this->__endian === self::LITTLE_ENDIAN)
        {
            $binarys = array_map(
                function ($binary)
                {
                    if (isset($binary[1]) === false)
                        return ord($binary);
                    else
                    {
                        $endian = ($this->__endian === self::LITTLE_ENDIAN)? 'v': 'n';
                        $endian = (isset($binary[2]) === false)? $endian: strtoupper($endian);
                    }
                    return unpack($endian . '*', $binary)[1];
                },
                $binarys
            );
        }
        return $binarys;
    }
}
?>
