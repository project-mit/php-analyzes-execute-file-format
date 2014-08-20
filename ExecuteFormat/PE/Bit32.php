<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\AbstractStreamIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\AbstractExecuteFormat;

class Bit32 extends AbstractExecuteFormat
{
    public function __construct(AbstractStreamIO &$streamio)
    {
        parent::__construct($streamio);
    }

    public function __destruct()
    {
        parent::__destruct();
    }

    public function getImageDosHeader()
    {
        $header = new ImageDosHeader();
        $header->magic = $this->_streamio->read(2, 0)->toString();
        $header->cblp = $this->_streamio->read(2)->toInteger();
        $header->cp = $this->_streamio->read(2)->toInteger();
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

    public function getImageNtHeaders(ImageDosHeader &$dosHeader = null)
    {
        // This method is needing to define of IMAGE_DOS_HEADER and
        // IMAGE_NT_HEADERS(IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER)
        if ($dosHeader === null)
            $dosHeader = $this->getImageDosHeader();

        $header = new ImageNtHeaders();

        // move to IMAGE_NT_HEADER's offset of file
        $header->signature = $this->_streamio->read(4, $dosHeader->lfanew)->toString();

        // get IMAGE_FILE_HEADER
        $header->fileheader->machine = $this->_streamio->read(2)->toInteger();
        $header->fileheader->numberOfSections = $this->_streamio->read(2)->toInteger();
        $header->fileheader->timeDateStamp = $this->_streamio->read(4)->toInteger();
        $header->fileheader->pointerToSymbolTable = $this->_streamio->read(4)->toInteger();
        $header->fileheader->numberOfSymbols = $this->_streamio->read(4)->toInteger();
        $header->fileheader->sizeOfOptionalHeader = $this->_streamio->read(2)->toInteger();
        $header->fileheader->characteristics = $this->_streamio->read(2)->toInteger();

        // get IMAGE_OPTIONAL_HEADER
        // The size of IMAGE_OPTIONAL_HEADER is put into `$header->fileheader->sizeOfOptionalHeader`.

        // The magic parameter of IMAGE_OPTIONAL_HEADER is 0x10B to 32bit mode of operating system.
        // This parameger on 64bit mode of operating system is 0x20B.
        $header->optionalheader->magic = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->majorLinkerVersion = $this->_streamio->read(1)->toInteger();
        $header->optionalheader->minorLinkerVersion = $this->_streamio->read(1)->toInteger();
        $header->optionalheader->sizeOfCode = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfInitializedData = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfUninitializedData = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->addressOfEntryPoint = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->baseOfCode = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->baseOfData = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->imageBase = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sectionAlignment = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->fileAlignment = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->majorOperatingSystemVersion = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->minorOperatingSystemVersion = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->majorImageVersion = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->minorImageVersion = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->majorSubsystemVersion = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->minorSubsystemVersion = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->win32VersionValue = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfImage = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfHeaders = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->checksum = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->subsystem = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->dllCharacteristics = $this->_streamio->read(2)->toInteger();
        $header->optionalheader->sizeOfStackReserve = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfStackCommit = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfHeapReserve = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->sizeOfHeapCommit = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->loaderFlags = $this->_streamio->read(4)->toInteger();
        $header->optionalheader->numberOfRvaAndSizes = $this->_streamio->read(4)->toInteger();

        for ($i = 0; $i < $header->optionalheader->numberOfRvaAndSizes; $i++)
        {
            $header->optionalheader->dataDirectory[$i] = new ImageDataDirectory();
            $header->optionalheader->dataDirectory[$i]->virtualAddress = $this->_streamio->read(4)->toInteger();
            $header->optionalheader->dataDirectory[$i]->size = $this->_streamio->read(4)->toInteger();
        }

        return $header;
    }

    public function getImageSectionHeader(ImageNtHeaders &$ntHeader = null)
    {
        // This method is needing to define of IMAGE_NT_HEADERS(IMAGE_FILE_HEADER and IMAGE_OPTIONAL_HEADER).
        if ($ntHeader === null)
            $ntHeader = $this->getImageNtHeaders();

        $headerArray = array();
        for ($i = 0; $i < $ntHeader->fileheader->numberOfSections; $i++)
        {
            $header = new ImageSectionHeader();
            $header->name = $this->_streamio->read($header::IMAGE_SIZEOF_SHORT_NAME)->toString();

            $header->misc['physicalAddress'] = $this->_streamio->read(4)->toInteger();
            $header->misc['virtualSize'] = $header->misc['physicalAddress'];

            $header->virtualAddress = $this->_streamio->read(4)->toInteger();
            $header->sizeOfRawData = $this->_streamio->read(4)->toInteger();
            $header->pointerToRawData = $this->_streamio->read(4)->toInteger();
            $header->pointerToRelocations = $this->_streamio->read(4)->toInteger();
            $header->pointerToLineNumbers = $this->_streamio->read(4)->toInteger();
            $header->numberOfRelocations = $this->_streamio->read(2)->toInteger();
            $header->numberOfLineNumbers = $this->_streamio->read(2)->toInteger();
            $header->characteristics = $this->_streamio->read(4)->toInteger();

            // get value to RVA of import address table
            if ($header->sizeOfRawData < $header->misc['virtualSize'])
            {
                $header->sizeOfRawData = ($header->misc['virtualSize'] - $header->misc['virtualSize'] % $ntHeader->optionalheader->fileAlignment) + $ntHeader->optionalheader->fileAlignment;
            }

            $headerArray[$i] = $header;
        }

        return $headerArray;
    }

    public function getImageImportDescriptors(ImageNtHeaders &$ntHeader = null, array &$sectionHeader = null)
    {
        if ($ntHeader === null)
            $ntHeader = $this->getImageNtHeaders();

        if ($sectionHeader === null)
            $sectionHeader = $this->getImageSectionHeader($ntHeader);

        // get value to RVA of import address table
        $iatInfo = $ntHeader->optionalheader->dataDirectory[ImageDataDirectory::IMPORT_DIRECTORY];
        foreach ($sectionHeader as $index => $section)
        {
            if ($iatInfo->virtualAddress >= $section->virtualAddress &&
                $iatInfo->virtualAddress <  $section->virtualAddress + $section->misc['virtualSize'])
            {
                // move file offset to Import Address Table
                $iatRAW = $iatInfo->virtualAddress - $section->virtualAddress + $section->pointerToRawData;
                $this->_streamio->read(0, $iatRAW);

                // get to length of Import Address Table
                $iatSections = $iatInfo->size / 20 - 1;
                $importDescriptorArray = array();
                for ($i = 0; $i < $iatSections; $i++)
                {
                    $importDescriptor = new ImageImportDescriptor();
                    $importDescriptor->dummyUnionName['characteristics'] = $this->_streamio->read(4)->toInteger();
                    $importDescriptor->dummyUnionName['originalFirstThunk'] = $importDescriptor->dummyUnionName['characteristics'];
                    $importDescriptor->timeDateStamp = $this->_streamio->read(4)->toInteger();
                    $importDescriptor->forwarderChain = $this->_streamio->read(4)->toInteger();
                    $importDescriptor->name = $this->_streamio->read(4)->toInteger();
                    $importDescriptor->firstThunk = $this->_streamio->read(4)->toInteger();

                    // RVA -> RAW
                    $importDescriptor->dummyUnionName['originalFirstThunk'] -= $section->virtualAddress;
                    $importDescriptor->dummyUnionName['originalFirstThunk'] += $section->pointerToRawData;
                    $importDescriptor->name -= $section->virtualAddress;
                    $importDescriptor->name += $section->pointerToRawData;
                    $importDescriptor->firstThunk -= $section->virtualAddress;
                    $importDescriptor->firstThunk += $section->pointerToRawData;

                    $importDescriptorArray[$i] = $importDescriptor;
                }

                return $importDescriptorArray;
            }
        }
        return null;
    }

    public function getListOfImportDLL(array &$importDescriptorArray = null)
    {
        if ($importDescriptorArray === null)
            $importDescriptorArray = $this->getImageImportDescriptors();

        $dllnameArray = array();
        foreach ($importDescriptorArray as $key => $import)
        {
            // move to offset of dll name
            $this->_streamio->read(0, $import->name);

            $dllname = '';
            while (($word = $this->_streamio->read(1)->toString()) !== "\x00")
                $dllname .= $word;

            $dllnameArray[$key] = $dllname;
        }

        return $dllnameArray;
    }
}
?>
