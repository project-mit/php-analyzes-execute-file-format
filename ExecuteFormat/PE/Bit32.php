<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

use AnalyzesExecuteFileFormat\Exception\NotSupportException;

use AnalyzesExecuteFileFormat\Lib\StreamIO\AbstractStreamIO;
use AnalyzesExecuteFileFormat\ExecuteFormat\AbstractExecuteFormat;

class Bit32 extends AbstractExecuteFormat
{
    private $rvaSectionArray = [];

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

        for ($i = 0; $i < ImageOptionalHeader::IMAGE_NUMBEROF_DIRECTORY_ENTRIES; $i++)
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

    public function getImageExportDescriptor(ImageNtHeaders &$ntHeader = null, array &$sectionHeader = null)
    {
        if ($ntHeader === null)
            $ntHeader = $this->getImageNtHeaders();

        if ($sectionHeader === null)
            $sectionHeader = $this->getImageSectionHeader($ntHeader);

        // target section directory header
        $targetDirectory = ImageDataDirectory::EXPORT_DIRECTORY;

        // get value to RVA of export address table
        $targetInfo = $ntHeader->optionalheader->dataDirectory[$targetDirectory];
        foreach ($sectionHeader as $index => $section)
        {
            if ($targetInfo->virtualAddress >= $section->virtualAddress &&
                $targetInfo->virtualAddress <  $section->virtualAddress + $section->misc['virtualSize'])
            {
                // move file offset to Export Address Table
                $targetRAW = $targetInfo->virtualAddress - $section->virtualAddress + $section->pointerToRawData;

                // get to length of Export Address Table
                $targetDescriptor = new ImageExportDescriptor();
                $targetDescriptor->characteristics = $this->_streamio->read(4, $targetRAW)->toInteger();
                $targetDescriptor->timeDateStamp = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->majorVersion = $this->_streamio->read(2)->toInteger();
                $targetDescriptor->minorVersion = $this->_streamio->read(2)->toInteger();
                $targetDescriptor->name = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->base = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->numberOfFunctions = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->numberOfNames = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->addressOfFunctions = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->addressOfNames = $this->_streamio->read(4)->toInteger();
                $targetDescriptor->addressOfNameOrdinals = $this->_streamio->read(4)->toInteger();

                $targetDescriptor->name -= $section->virtualAddress;
                $targetDescriptor->name += $section->pointerToRawData;
                $targetDescriptor->addressOfNames -= $section->virtualAddress;
                $targetDescriptor->addressOfNames += $section->pointerToRawData;

                // RVA -> RAW need to section information
                $this->rvaSectionArray[$targetDirectory] = [
                    'virtualAddress' => $section->virtualAddress,
                    'pointerToRawData' => $section->pointerToRawData
                ];

                return $targetDescriptor;
            }
        }
        return new ImageExportDescriptor();
    }

    public function getListOfExportFileName(ImageExportDescriptor &$exportDescriptor = null)
    {
        if ($exportDescriptor === null)
            $exportDescriptor = $this->getImageExportDescriptors();

        if ($exportDescriptor->name == 0) return '';

        // move to offset of dll name
        $this->_streamio->read(0, $exportDescriptor->name);

        $dllname = '';
        while (($word = $this->_streamio->read(1)->toString()) !== "\x00")
            $dllname .= $word;

        $dllname = strtolower($dllname);

        return $dllname;
    }

    public function getListOfExportFunction(ImageExportDescriptor &$exportDescriptor = null)
    {
        if ($exportDescriptor === null)
            $exportDescriptor = $this->getImageExportDescriptors();

        // target section directory header
        $targetDirectory = ImageDataDirectory::EXPORT_DIRECTORY;

        $functionArray = array();
        $rawInfo = $this->rvaSectionArray[$targetDirectory];
        for ($i = 0; $i < $exportDescriptor->numberOfNames; $i++)
        {
            $funcnameAddress = $this->_streamio->read(4, $exportDescriptor->addressOfNames + $i * 4)->toInteger();
            $funcnameAddress -= $rawInfo['virtualAddress'];
            $funcnameAddress += $rawInfo['pointerToRawData'];
            $this->_streamio->read(0, $funcnameAddress);

            $funcname = '';
            while (($word = $this->_streamio->read(1)->toString()) !== "\x00")
                $funcname .= $word;

            $funcOrdinal = $this->_streamio->read(2, $exportDescriptor->addressOfNameOrdinals + $i * 2)->toInteger();

            $funcAddress = $this->_streamio->read(4, $exportDescriptor->addressOfFunctions + $i * 4)->toInteger();

            $functionArray[] = [
                'ordinal' => $funcOrdinal,
                'function' => $funcname,
                'address' => $funcAddress
            ];
        }

        return $functionArray;
    }

    public function getImageImportDescriptors(ImageNtHeaders &$ntHeader = null, array &$sectionHeader = null)
    {
        if ($ntHeader === null)
            $ntHeader = $this->getImageNtHeaders();

        if ($sectionHeader === null)
            $sectionHeader = $this->getImageSectionHeader($ntHeader);

        // target section directory header
        $targetDirectory = ImageDataDirectory::IMPORT_DIRECTORY;

        // get value to RVA of import address table
        $targetInfo = $ntHeader->optionalheader->dataDirectory[$targetDirectory];
        foreach ($sectionHeader as $index => $section)
        {
            if ($targetInfo->virtualAddress >= $section->virtualAddress &&
                $targetInfo->virtualAddress <  $section->virtualAddress + $section->misc['virtualSize'])
            {
                // move file offset to Import Address Table
                $targetRAW = $targetInfo->virtualAddress - $section->virtualAddress + $section->pointerToRawData;

                $targetDescriptorArray = array();
                for ($i = 0; ; $i++)
                {
                    $targetDescriptor = new ImageImportDescriptor();
                    $targetDescriptor->dummyUnionName['characteristics'] = $this->_streamio->read(4, $targetRAW + $i * 20)->toInteger();
                    $targetDescriptor->dummyUnionName['ordiginalFirstThunk'] = $targetDescriptor->dummyUnionName['characteristics'];
                    $targetDescriptor->timeDateStamp = $this->_streamio->read(4)->toInteger();
                    $targetDescriptor->forwarderChain = $this->_streamio->read(4)->toInteger();
                    $targetDescriptor->name = $this->_streamio->read(4)->toInteger();
                    $targetDescriptor->firstThunk = $this->_streamio->read(4)->toInteger();

                    $endOfDescriptor  = $targetDescriptor->dummyUnionName['ordiginalFirstThunk'];
                    $endOfDescriptor += $targetDescriptor->timeDateStamp;
                    $endOfDescriptor += $targetDescriptor->forwarderChain;
                    $endOfDescriptor += $targetDescriptor->name;
                    $endOfDescriptor += $targetDescriptor->firstThunk;
                    // if value of `$endOfDescriptor` is zero, end-of-structure.
                    if ($endOfDescriptor === 0)
                        break;

                    // RVA -> RAW
                    $targetDescriptor->dummyUnionName['ordiginalFirstThunk'] -= $section->virtualAddress;
                    $targetDescriptor->dummyUnionName['ordiginalFirstThunk'] += $section->pointerToRawData;
                    $targetDescriptor->name -= $section->virtualAddress;
                    $targetDescriptor->name += $section->pointerToRawData;
                    $targetDescriptor->firstThunk -= $section->virtualAddress;
                    $targetDescriptor->firstThunk += $section->pointerToRawData;

                    $targetDescriptorArray[] = $targetDescriptor;
                }

                // RVA -> RAW need to section information
                $this->rvaSectionArray[$targetDirectory] = [
                    'virtualAddress' => $section->virtualAddress,
                    'pointerToRawData' => $section->pointerToRawData
                ];

                return $targetDescriptorArray;
            }
        }
        return array();
    }

    public function getListOfImportDLL(array $importDescriptorArray = null)
    {
        if ($importDescriptorArray === null)
            $importDescriptorArray = $this->getImageImportDescriptors();

        $dllnameArray = array();
        foreach ($importDescriptorArray as $key => $import)
        {
            // move to offset of dll name
            $this->_streamio->read(0, $import->name);

            $dllnameArray[$key] = '';
            while (($word = $this->_streamio->read(1)->toString()) !== "\x00")
                $dllnameArray[$key] .= $word;

            $dllnameArray[$key] = strtolower($dllnameArray[$key]);
        }

        return $dllnameArray;
    }

    public function getListOfImportFunction(array $importDescriptorArray = null)
    {
        if ($importDescriptorArray === null)
            $importDescriptorArray = $this->getImageImportDescriptors();

        // target section directory header
        $targetDirectory = ImageDataDirectory::IMPORT_DIRECTORY;

        $functionArray = array();
        $rawInfo = $this->rvaSectionArray[$targetDirectory];
        foreach ($importDescriptorArray as $key => $import)
        {
            // move to offset of dll name
            $this->_streamio->read(0, $import->name);

            $dllname = '';
            while (($word = $this->_streamio->read(1)->toString()) !== "\x00")
                $dllname .= $word;

            $importThunkDataArray = array();
            // move to offset of dll into functions name
            for ($i = 0; ($importThunkData = $this->_streamio->read(4, $import->firstThunk + $i * 4)->toInteger()) !== 0; $i++)
            {
                $importThunk = new ImageThunkData();
                $importByName = new ImageImportByName();
                $importByName->hint = 0;
                $importByName->name = 0;
                
                // if MSB of $importThunkData is set, the value of IMAGE_THUNK_DATA is used to method of `ordinal`.
                if (($importThunkData >> (4 * 8 - 1)) === 0b1)
                {
                    $importByName->name = $importThunkData & 0x0000ffff;
                }
                else
                {
                    $importThunk->u1['forwarderString'] = $importThunkData;
                    $importThunk->u1['function'] = &$importThunk->u1['forwarderString'];
                    $importThunk->u1['ordinal'] = &$importThunk->u1['forwarderString'];
                    $importThunk->u1['addressOfData'] = &$importThunk->u1['forwarderString'];

                    // get to IMAGE_IMPORT_BY_NAME
                    $importThunk->u1['addressOfData'] -= $rawInfo['virtualAddress'];
                    $importThunk->u1['addressOfData'] += $rawInfo['pointerToRawData'];

                    // move to offset of IMAGE_IMPORT_BY_NAME
                    $importByName->hint = $this->_streamio->read(2, $importThunk->u1['addressOfData'])->toInteger();
                    $importByName->name = '';
                    while (($word = $this->_streamio->read(1)->toString()) !== "\x00")
                        $importByName->name .= $word;
                }
                $importThunkDataArray[] = [
                    'importByName' => $importByName,
                    'importThunk' => $importThunk
                ];
            }

            $functionArray[$key] = $importThunkDataArray;
        }

        return $functionArray;
    }

    public function getProcAddress($dllname, $funcname, array &$dllArray = null, array &$functionArray = null)
    {
        if ($dllArray === null)
            $dllArray = $this->getListOfImportDLL();

        if ($functionArray === null)
            $functionArray = $this->getListOfImportFunction();

        // target section directory header
        $targetDirectory = ImageDataDirectory::IMPORT_DIRECTORY;

        $rawInfo = $this->rvaSectionArray[$targetDirectory];
        foreach ($dllArray as $dllIndex => $dll)
        {
            if ($dll === $dllname)
            {
                foreach ($functionArray[$dllIndex] as $funcIndex => $function)
                {
                    if (is_string($function['importByName']->name) === true)
                    {
                        if ($function['importByName']->name === $funcname)
                        {
                            return $function['importThunk']->u1['function'];
                        }
                    }
                    /*
                    else
                    {
                        // NotSupported
                        // $dllname -> pe analyzes -> Export Address Table
                    }
                    */
                }
                return null;
            }
        }
    }
}
?>
