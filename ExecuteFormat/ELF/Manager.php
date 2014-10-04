<?php
/**
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 *
 * @copyright ProJectMIT
 * @license   http://www.opensource.org/licenses/MIT-License MIT License
 */
namespace AnalyzesExecuteFileFormat\ExecuteFormat\ELF;

use AnalyzesExecuteFileFormat\Exception\NotSupportException,
    AnalyzesExecuteFileFormat\Exception\IOException;

use AnalyzesExecuteFileFormat\Lib\FileIO;

class Manager
{
    const OPERATING_SYSTEM_32BIT_MODE = 0x0001;
    const OPERATING_SYSTEM_64BIT_MODE = 0x0002;

    protected $_streamio = null;

    public function __construct($streamio)
    {
        if (version_compare(PHP_VERSION, '5.4.0') < 0)
            throw new NotSupportException('of PHP_VERSION(' . PHP_VERSION . ')');

        $this->_streamio = new FileIO($streamio);
    }

    public function __destruct()
    {
        unset($this->_streamio);
    }

    public function getObjectFromBitMode()
    {
        $osmode = $this->_getOperatingSystemMode();
        if ($osmode === 0)
            throw new IOException('This value about mode on the operating system is invalid.');

        if ($osmode === $this::OPERATING_SYSTEM_32BIT_MODE)
            return new Bit32($this->_streamio);

        if ($osmode === $this::OPERATING_SYSTEM_64BIT_MODE)
            return new Bit64($this->_streamio);

        return null;
    }

    protected function _isExecute()
    {
        $e_ident = $this->_streamio->read(4, 0)->toInteger();
        if ($e_ident !== 0x464c457f)
            return false;

        $e_type = $this->_streamio->read(2, 16)->toInteger();
        if ($e_type === 0x0002)
            return true;

        return false;
    }

    protected function _getOperatingSystemMode()
    {
        if ($this->_isExecute() === false)
            throw new IOException('This file is not executeable !!');

        $el_class = $this->_streamio->read(1, 4)->toInteger();
        if ($el_class === $this::OPERATING_SYSTEM_32BIT_MODE || $el_class === $this::OPERATING_SYSTEM_64BIT_MODE)
            return $el_class;

        return 0;
    }
}
?>
