<?php
/**
 * For the full copyright and license information, please view the LICENSE file
 * that was distributed with this source code.
 *
 * @copyright ProJectMIT
 * @license   http://www.opensource.org/licenses/MIT-License MIT License
 */
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

use AnalyzesExecuteFileFormat\Exception\NotSupportException,
    AnalyzesExecuteFileFormat\Exception\IOException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\AbstractStreamIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\AbstractExecuteFormat;

class ExecuteFormat
{
    const OPERATING_SYSTEM_32BIT_MODE = 0x10b;
    const OPERATING_SYSTEM_64BIT_MODE = 0x20b;

    protected $_streamio = null;

    public function __construct(AbstractStreamIO &$streamio)
    {
        if (version_compare(PHP_VERSION, '5.4.0') < 0)
            throw new NotSupportException('of PHP_VERSION(' . PHP_VERSION . ')');

        $this->_streamio = $streamio;
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
        if ($this->_streamio->read(2, 0)->toInteger() === 0x5a4d)
            return true;
        return false;
    }

    protected function _getOperatingSystemMode()
    {
        if ($this->_isExecute() === false)
            throw new IOException('This file is not executeable !!');

        $lfanew = $this->_streamio->read(4, 2 * 30)->toInteger();
        $signature = $this->_streamio->read(4, $lfanew)->toInteger();

        if ($signature !== 0x00004550)
            throw new IOException('This file is not invalid IMAGE_OPTIONAL_HEADER !!');

        $magic = $this->_streamio->read(2, $lfanew + 4 * 6)->toInteger();
        if ($magic === 0x10b || $magic === 0x20b)
            return $magic;

        return 0;
    }
}
?>
