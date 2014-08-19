<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\AbstractStreamIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\AbstractExecuteFormat;

class Bit32 extends AbstractExecuteFormat
{
    public function __construct(AbstractStreamIO &$streamio)
    {
        // not supported PE 32bit mode
        //throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        parent::__construct($streamio);
    }

    public function __destruct()
    {
        parent::__destruct();
    }

    public function getImageDosHeader()
    {
        $header = new ImageDosHeader();
        $header->magic = $this->_streamio->read(2)->toString();
        $header->cblp = $this->_streamio->read(2)->toInteger();
        $header->crlc = $this->_streamio->read(2)->toInteger();
        $header->cparhdr = $this->_streamio->read(2)->toInteger();
        $header->minalloc = $this->_streamio->read(2)->toInteger();
        $header->maxalloc = $this->_streamio->read(2)->toInteger();
        $header->ss = $this->_streamio->read(2)->toInteger();
        $header->sp = $this->_streamio->read(2)->toInteger();
        $header->csum = $this->_streamio->read(2)->toInteger();
        $header->ip = $this->_streamio->read(2)->toInteger();
        $header->cs = $this->_streamio->read(2)->toInteger();
        $header->lfarlc = $this->_streamio->read(2)->toInteger();
        $header->ovno = $this->_streamio->read(2)->toInteger();
        $header->reservd1 = $this->_streamio->read(2 * 4)->toIntArray(2);
        $header->oemid = $this->_streamio->read(2)->toInteger();
        $header->oeminfo = $this->_streamio->read(2)->toInteger();
        $header->reservd2 = $this->_streamio->read(2 * 10)->toIntArray(2);
        $header->lfanew = $this->_streamio->read(4)->toInteger();

        return $header;
    }
}
?>
