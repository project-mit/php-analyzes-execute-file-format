<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\ELF;

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\AbstractStreamIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\AbstractExecuteFormat;

class Bit32 extends AbstractExecuteFormat
{
    public function __construct(&$streamio)
    {
        // not supported ELF 32bit mode
        //throw new NotSupportException(__CLASS__ . '::' . __FUNCTION__);

        parent::__construct($streamio);
    }

    public function __destruct()
    {
        parent::__destruct();
    }

    public function getElfHeader()
    {
        $header = new ElfHeader();
        $header->e_ident['el_mag0'] = $this->_streamio->read(1, 0)->toInteger();
        $header->e_ident['el_mag3'] = $this->_streamio->read(3)->toString();
        $header->e_ident['el_class'] = $this->_streamio->read(1)->toInteger();
        $header->e_ident['el_data'] = $this->_streamio->read(1)->toInteger();
        $header->e_ident['el_version'] = $this->_streamio->read(1)->toInteger();
        $header->e_ident['el_osabi'] = $this->_streamio->read(1)->toInteger();
        $header->e_ident['el_abiversion'] = $this->_streamio->read(1)->toInteger();
        $header->e_ident['el_pad'] = $this->_streamio->read(7)->toIntArray(1);
        $header->e_type = $this->_streamio->read(2)->toInteger();
        $header->e_machine = $this->_streamio->read(2)->toInteger();
        $header->e_version = $this->_streamio->read(4)->toInteger();
        $header->e_entry = $this->_streamio->read(4)->toInteger();
        $header->e_phoff = $this->_streamio->read(4)->toInteger();
        $header->e_shoff = $this->_streamio->read(4)->toInteger();
        $header->e_flags = $this->_streamio->read(4)->toInteger();
        $header->e_ehsize = $this->_streamio->read(2)->toInteger();
        $header->e_phentsize = $this->_streamio->read(2)->toInteger();
        $header->e_phnum = $this->_streamio->read(2)->toInteger();
        $header->e_shentsize = $this->_streamio->read(2)->toInteger();
        $header->e_shnum = $this->_streamio->read(2)->toInteger();
        $header->e_shstrndx = $this->_streamio->read(2)->toInteger();
        return $header;
    }
}
?>
