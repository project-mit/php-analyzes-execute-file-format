<?php
// 파일 헤더값 강제 변경
header('Content-Type: text/html; charset=utf-8');
// EXE PE HEADER 분석

// 오류레벨 최상위로 설정
error_reporting(E_ALL);

// 분석할 파일값 얻어오기
if (isset($_GET['file']) == true)
{
	$file = '/var/ftp/pub/'.$_GET['file'];
	if (!file_exists($file))
		unset($file);
}
?>
<html>
<head>
	<title>PE HEADER VIEWER</title>
	<style type="text/css">
	body {font-size:11px; font-family:'dottum'; line-height:16px;}
	</style>
</head>
<body>
<?php
if (isset($file) == false)
{
	echo '읽어올 파일의 형식을 $_GET[\'file\'] 으로 설정해 주십시오<br />';
	echo '파일 목록 : <br />';

	$handle = dir('/var/ftp/pub/');
	while ($develop_list = $handle->read())
	{
		switch($develop_list)
		{
		case '.':
		case '..':
			break;
		default:
			echo '<a href="?file='.$develop_list.'">'.$develop_list.'</a><br />';
			break;
		}
	}
	$handle->close();
}
else
{
	// 본격 PE HEADER VIEWER 시작
	$byte = new Byte($file);

	echo '<h2><a href="'.$file.'">'.$file.'</a> - PE HEADER</h2>';

	echo '<h3>IMAGE_DOS_HEADER</h3>';
	// DOS_HEADER 64Byte
	//
	// DOS_Signature
	$dos_signature = $byte->getReadBytes(2);
	$dos_signature = $byte->getLittleEndian($dos_signature);
	if ($dos_signature != 0x5a4d)
	{
		echo '<br />';
		echo '올바른 PE 헤더를 가지고 있지 않는 파일 입니다.';
		exit;
	}
	echo 'Magic number = "';
	echo $dos_signature;
	echo '"';

	echo '<br />';

	// DOS_PartPag
	$dos_partpag = $byte->getReadBytes(2);
	$dos_partpag = $byte->getLittleEndian($dos_partpag);
	$dos_partpag = hexdec($dos_partpag);
	echo 'Bytes on last page of file = "';
	echo $dos_partpag;
	echo '"';

	echo '<br />';

	// DOS_PageCnt
	$dos_pagecnt = $byte->getReadBytes(2);
	$dos_pagecnt = $byte->getLittleEndian($dos_pagecnt);
	$dos_pagecnt = hexdec($dos_pagecnt);
	echo 'Pages in file = "';
	echo $dos_pagecnt;
	echo '"';

	echo '<br />';

	// DOS_ReloCnt
	$dos_relocnt = $byte->getReadBytes(2);
	$dos_relocnt = $byte->getLittleEndian($dos_relocnt);
	$dos_relocnt = hexdec($dos_relocnt);
	echo 'Relocations = "';
	echo $dos_relocnt;
	echo '"';

	echo '<br />';

	// DOS_HdrSize
	$dos_hdrsize = $byte->getReadBytes(2);
	$dos_hdrsize = $byte->getLittleEndian($dos_hdrsize);
	$dos_hdrsize = hexdec($dos_hdrsize);
	echo 'Size of header in pargraphs = "';
	echo $dos_hdrsize;
	echo '"';

	echo '<br />';

	// DOS_MinMem
	$dos_minmem = $byte->getReadBytes(2);
	$dos_minmem = $byte->getLittleEndian($dos_minmem);
	$dos_minmem = hexdec($dos_minmem);
	echo 'Minimum extra paragraphs needed = "';
	echo $dos_minmem;
	echo '"';

	echo '<br />';

	// DOS_MaxMem
	$dos_maxmem = $byte->getReadBytes(2);
	$dos_maxmem = $byte->getLittleEndian($dos_maxmem);
	$dos_maxmem = hexdec($dos_maxmem);
	echo 'Maximum extra paragrphs needed = "';
	echo $dos_maxmem;
	echo '"';

	echo '<br />';

	// DOS_RelSS
	$dos_relss = $byte->getReadBytes(2);
	$dos_relss = $byte->getLittleEndian($dos_relss);
	echo 'Initial (relative) SS value = "';
	echo $dos_relss;
	echo '"';

	echo '<br />';

	// DOS_ExeSP
	$dos_exesp = $byte->getReadBytes(2);
	$dos_exesp = $byte->getLittleEndian($dos_exesp);
	echo 'Initial SP value = "';
	echo $dos_exesp;
	echo '"';

	echo '<br />';

	// DOS_ChkSum
	$dos_chksum = $byte->getReadBytes(2);
	$dos_chksum = $byte->getLittleEndian($dos_chksum);
	echo 'Checksum = "';
	echo $dos_chksum;
	echo '"';

	echo '<br />';

	// DOS_ExeIP
	$dos_exeip = $byte->getReadBytes(2);
	$dos_exeip = $byte->getLittleEndian($dos_exeip);
	echo 'Initial IP value = "';
	echo $dos_exeip;
	echo '"';

	echo '<br />';

	// DOS_RelCS
	$dos_relcs = $byte->getReadBytes(2);
	$dos_relcs = $byte->getLittleEndian($dos_relcs);
	echo 'Initial (relative) CS value = "';
	echo $dos_relcs;
	echo '"';

	echo '<br />';

	// DOS_RelocOffset
	$dos_relocoffset = $byte->getReadBytes(2);
	$dos_relocoffset =  $byte->getLittleEndian($dos_relocoffset);
	echo 'File address of relocation table = "';
	echo $dos_relocoffset;
	echo '"';

	echo '<br />';

	// DOS_Overlay
	$dos_overlay = $byte->getReadBytes(2);
	$dos_overlay = $byte->getLittleEndian($dos_overlay);
	echo 'Overlay number = "';
	echo $dos_overlay;
	echo '"';

	echo '<br />';

	// DOS_Reserved1[4]
	$dos_reserved1 = array();
	$dos_reserved1[0] = $byte->getReadBytes(2);
	$dos_reserved1[1] = $byte->getReadBytes(2);
	$dos_reserved1[2] = $byte->getReadBytes(2);
	$dos_reserved1[3] = $byte->getReadBytes(2);
	$dos_reserved1[0] = $byte->getLittleEndian($dos_reserved1[0]);
	$dos_reserved1[1] = $byte->getLittleEndian($dos_reserved1[1]);
	$dos_reserved1[2] = $byte->getLittleEndian($dos_reserved1[2]);
	$dos_reserved1[3] = $byte->getLittleEndian($dos_reserved1[3]);
	echo 'Reserved words = "';
	echo $dos_reserved1[0];
	echo ', ';
	echo $dos_reserved1[1];
	echo ', ';
	echo $dos_reserved1[2];
	echo ', ';
	echo $dos_reserved1[3];
	echo '"';

	echo '<br />';

	// DOS_OEM_ID
	$dos_oem_id = $byte->getReadBytes(2);
	$dos_oem_id = $byte->getLittleEndian($dos_oem_id);
	echo 'OEM identifier (for e_oeminfo) = "';
	echo $dos_oem_id;
	echo '"';

	echo '<br />';

	// DOS_OEM_Info
	$dos_oem_info = $byte->getReadBytes(2);
	$dos_oem_info = $byte->getLittleEndian($dos_oem_info);
	echo 'OEM information; e_oemid specific = "';
	echo $dos_oem_info;
	echo '"';

	echo '<br />';

	// DOS_Reserved2[10]
	$dos_reserved2 = array();
	$dos_reserved2[0] = $byte->getReadBytes(2);
	$dos_reserved2[1] = $byte->getReadBytes(2);
	$dos_reserved2[2] = $byte->getReadBytes(2);
	$dos_reserved2[3] = $byte->getReadBytes(2);
	$dos_reserved2[4] = $byte->getReadBytes(2);
	$dos_reserved2[5] = $byte->getReadBytes(2);
	$dos_reserved2[6] = $byte->getReadBytes(2);
	$dos_reserved2[7] = $byte->getReadBytes(2);
	$dos_reserved2[8] = $byte->getReadBytes(2);
	$dos_reserved2[9] = $byte->getReadBytes(2);
	$dos_reserved2[0] = $byte->getLittleEndian($dos_reserved2[0]);
	$dos_reserved2[1] = $byte->getLittleEndian($dos_reserved2[1]);
	$dos_reserved2[2] = $byte->getLittleEndian($dos_reserved2[2]);
	$dos_reserved2[3] = $byte->getLittleEndian($dos_reserved2[3]);
	$dos_reserved2[4] = $byte->getLittleEndian($dos_reserved2[4]);
	$dos_reserved2[5] = $byte->getLittleEndian($dos_reserved2[5]);
	$dos_reserved2[6] = $byte->getLittleEndian($dos_reserved2[6]);
	$dos_reserved2[7] = $byte->getLittleEndian($dos_reserved2[7]);
	$dos_reserved2[8] = $byte->getLittleEndian($dos_reserved2[8]);
	$dos_reserved2[9] = $byte->getLittleEndian($dos_reserved2[9]);
	echo 'Reserved words = "';
	echo $dos_reserved2[0];
	echo ', ';
	echo $dos_reserved2[1];
	echo ', ';
	echo $dos_reserved2[2];
	echo ', ';
	echo $dos_reserved2[3];
	echo ', ';
	echo $dos_reserved2[4];
	echo ', ';
	echo $dos_reserved2[5];
	echo ', ';
	echo $dos_reserved2[6];
	echo ', ';
	echo $dos_reserved2[7];
	echo ', ';
	echo $dos_reserved2[8];
	echo ', ';
	echo $dos_reserved2[9];
	echo '"';

	echo '<br />';

	// DOS_PEOffset
	$dos_peoffset = $byte->getReadBytes(4);
	$dos_peoffset = $byte->getLittleEndian($dos_peoffset);
	echo 'File address of new exe header = "';
	echo $dos_peoffset;
	echo '"';

	echo '<h3>IMAGE_NT_HEADERS</h3>';

	$byte->setPointer($dos_peoffset);
	$pe_offset = $byte->file_offset;
	// IMAGE_NT_SIGNATURE[4]
	$image_nt_signature = array();
	$image_nt_signature[0] = chr(hexdec($byte->getReadBytes(1)));
	$image_nt_signature[1] = chr(hexdec($byte->getReadBytes(1)));
	$image_nt_signature[2] = hexdec($byte->getReadBytes(1));
	$image_nt_signature[3] = hexdec($byte->getReadBytes(1));
	echo 'IMAGE_NT_SIGNATURE[4] = "';
	echo $image_nt_signature[0];
	echo $image_nt_signature[1];
	echo ', ';
	echo $image_nt_signature[2];
	echo ', ';
	echo $image_nt_signature[3];
	echo '"';

	echo '<h3>IMAGE_FILE_HEADER</h3>';

	// Machine
	$machine = $byte->getReadBytes(2);
	$machine = $byte->getLittleEndian($machine);
	echo '파일이 실행되는 CPU의 ID = "';
	echo $machine;
	echo '" ; ';
	if ($machine == 0x0000) echo 'IMAGE_FILE_MACHINE_UNKNOWN';
	if ($machine == 0x014c) echo 'IMAGE_FILE_MACHINE_I386';			// little-endian
	if ($machine == 0x0162) echo 'IMAGE_FILE_MACHINE_R3000';		// little-endian
	if ($machine == 0x0166) echo 'IMAGE_FILE_MACHINE_R4000';		// little-endian
	if ($machine == 0x0168) echo 'IMAGE_FILE_MACHINE_R10000';		// little-endian
	if ($machine == 0x0169) echo 'IMAGE_FILE_MACHINE_WCEMIPSV2';	// little-endian
	if ($machine == 0x0184) echo 'IMAGE_FILE_MACHINE_ALPHA';		// Alpha_AXP
	if ($machine == 0x01f0) echo 'IMAGE_FILE_MACHINE_POWERPC';		// little-endian
	if ($machine == 0x01a2) echo 'IMAGE_FILE_MACHINE_SH3';			// little-endian
	if ($machine == 0x01a4) echo 'IMAGE_FILE_MACHINE_SH3E';			// little-endian
	if ($machine == 0x01a6) echo 'IMAGE_FILE_MACHINE_SH4';			// little-endian
	if ($machine == 0x01c0) echo 'IMAGE_FILE_MACHINE_ARM';			// little-endian
	if ($machine == 0x01c2) echo 'IMAGE_FILE_MACHINE_THUMB';
	if ($machine == 0x0200) echo 'IMAGE_FILE_MACHINE_IA64';			// Intel 64
	if ($machine == 0x0266) echo 'IMAGE_FILE_MACHINE_MIPS16';		// MIPS
	if ($machine == 0x0284) echo 'IMAGE_FILE_MACHINE_ALPHA64';		// ALPHA64
	if ($machine == 0x0366) echo 'IMAGE_FILE_MACHINE_MIPSFPU';		// MIPS
	if ($machine == 0x0466) echo 'IMAGE_FILE_MACHINE_MIPSFPU16';	// MIPS
	if ($machine == 0x0520) echo 'IMAGE_FILE_MACHINE_TRICORE';		// Infineon
	if ($machine == 0x0cef) echo 'IMAGE_FILE_MACHINE_CEF';
	if ($machine == 0x0ebc) echo 'IMAGE_FILE_MACHINE_EBC';			// EFI Byte Code
	if ($machine == 0x8664) echo 'IMAGE_FILE_MACHINE_AMD64';		// AMD64 (K8)
	if ($machine == 0x9041) echo 'IMAGE_FILE_MACHINE_M32R';			// M32R little-endian
	if ($machine == 0xc0ee) echo 'IMAGE_FILE_MACHINE_CEE';

	echo '<br />';

	// NumberOfSections
	$number_of_sections = $byte->getReadBytes(2);
	$number_of_sections = $byte->getLittleEndian($number_of_sections);
	$number_of_sections = hexdec($number_of_sections);
	echo 'IMAGE_SECTION_HEADER 의 개수와 해당 섹션의 개수 = "';
	echo $number_of_sections;
	echo '"';

	echo '<br />';

	// TimeDateStamp
	$time_date_stamp = $byte->getReadBytes(4);
	$time_date_stamp = $byte->getLittleEndian($time_date_stamp);
	echo '1970.1.1 부터 해당 파일을 만들어낸 시점까지의 시간의 초 = "';
	echo $time_date_stamp;
	echo '"';
	echo ' ; ';
	echo gmdate('Y.m.d H:i:s', hexdec($time_date_stamp));

	echo '<br />';

	// PointerToSymbolTable
	$pointer_to_symbol_table = $byte->getReadBytes(4);
	$pointer_to_symbol_table = $byte->getLittleEndian($pointer_to_symbol_table);
	$pointer_to_symbol_table = hexdec($pointer_to_symbol_table);
	echo '디버그 정보를 가진 PE파일에서 사용 (PointerToSymbolTable) = "';
	echo $pointer_to_symbol_table;
	echo '"';

	echo '<br />';

	// NumberOfSymbols
	$number_of_symbols = $byte->getReadBytes(4);
	$number_of_symbols = $byte->getLittleEndian($number_of_symbols);
	$number_of_symbols = hexdec($number_of_symbols);
	echo '디버그 정보를 가진 PE파일에서 사용 (NumberOfSymbols) = "';
	echo $number_of_symbols;
	echo '"';

	echo '<br />';

	// SizeOfOptionalHeader
	$size_of_optional_header = $byte->getReadBytes(2);
	$size_of_optional_header = $byte->getLittleEndian($size_of_optional_header);
	$size_of_optional_header = hexdec($size_of_optional_header);
	echo 'IMAGE_OPTIONAL_HEADER 바이트수 = "';
	echo $size_of_optional_header;
	echo '"';

	echo '<br />';

	// Characterstics
	$characterstics = $byte->getReadBytes(2);
	$characterstics = $byte->getLittleEndian($characterstics);
	$characterstics = hexdec($characterstics);
	echo 'PE파일에 대한 특정 정보에 대한 플래그 = "';
	echo $characterstics;
	echo '" ; ';
	$characterstics_array = array();
	if ($characterstics & 0x0001) $characterstics_array[] = 'IMAGE_FILE_RELOCS_STRIPPED';
	if ($characterstics & 0x0002) $characterstics_array[] = 'IMAGE_FILE_EXECUTABLE_IMAGE';
	if ($characterstics & 0x0004) $characterstics_array[] = 'IMAGE_FILE_LINE_NUMS_STRIPPED';
	if ($characterstics & 0x0008) $characterstics_array[] = 'IMAGE_FILE_LOCAL_SYMS_STRIPPED';
	if ($characterstics & 0x0010) $characterstics_array[] = 'IMAGE_FILE_AGGRESIVE_WS_TRIM';
	if ($characterstics & 0x0020) $characterstics_array[] = 'IMAGE_FILE_LARGE_ADDRESS_AWARE';
	if ($characterstics & 0x0080) $characterstics_array[] = 'IMAGE_FILE_BYTES_REVERSED_LO';
	if ($characterstics & 0x0100) $characterstics_array[] = 'IMAGE_FILE_32BIT_MACHINE';
	if ($characterstics & 0x0200) $characterstics_array[] = 'IMAGE_FILE_DEBUG_STRIPPED';
	if ($characterstics & 0x0400) $characterstics_array[] = 'IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP';
	if ($characterstics & 0x0800) $characterstics_array[] = 'IMAGE_FILE_NET_RUN_FROM_SWAP';
	if ($characterstics & 0x1000) $characterstics_array[] = 'IMAGE_FILE_SYSTEM';
	if ($characterstics & 0x2000) $characterstics_array[] = 'IMAGE_FILE_DLL';
	if ($characterstics & 0x4000) $characterstics_array[] = 'IMAGE_FILE_UP_SYSTEM_ONLY';
	if ($characterstics & 0x8000) $characterstics_array[] = 'IMAGE_FILE_BYTES_REVERSED_HI';
	echo implode('<b> | </b>', $characterstics_array);

	echo '<br />';

	// PE 분석한 파일의 종류
	$pe_file_type = 'EXE';
	if ($characterstics & 0x2000) $pe_file_type = 'DLL';
	echo 'PE 분석한 파일의 종류 = "';
	echo '*.'.$pe_file_type;
	echo '"';

	echo '<h3>IMAGE_OPTIONAL_HEADER</h3>';

	$ioh_offset = $pe_offset+24;
	// Magic
	$magic = $byte->getReadBytes(2);
	$magic = $byte->getLittleEndian($magic);
	echo 'IMAGE_OPTIONAL_HEADER 를 나타내는 시그네쳐 = "';
	echo $magic;
	echo '"';
	echo ' ; ';
	if ($magic == 0x010b) echo 'IMAGE_NT_OPTIONAL_HDR32_MAGIC';
	if ($magic == 0x020b) echo 'IMAGE_NT_OPTIONAL_HDR64_MAGIC';
	if ($magic == 0x0107) echo 'IMAGE_ROM_OPTIONAL_HDR_MAGIC';

	// 64bit 운영체제 PE32+ 정의
	if ($magic == 0x020b) define('PE_ADDR_SIZE', 8);
	// 32bit 운영체제 PE32 정의
	if ($magic != 0x020b) define('PE_ADDR_SIZE', 4);

	echo '<br />';

	// 실행 가능한 운영체제 종류
	if (PE_ADDR_SIZE == 4) $os_type = '32bit';
	if (PE_ADDR_SIZE == 8) $os_type = '64bit';
	echo '사용 가능한 운영체제의 종류 = "';
	echo $os_type;
	echo '"';

	echo '<br />';

	// MajorLinkerVersion, MinorLinkerVersion
	$major_linker_version = $byte->getReadBytes(1);
	$major_linker_version = hexdec($major_linker_version);
	echo '파일 만들어낸 링커의 버전 (MajorLinkerVersion) = "';
	echo $major_linker_version;
	echo '"';

	echo '<br />';

	// MinorLinkerVersion
	$minor_linker_version = $byte->getReadBytes(1);
	$minor_linker_version = hexdec($minor_linker_version);
	echo '파일 만들어낸 링커의 버전 (MinorLinkerVersion) = "';
	echo $minor_linker_version;
	echo '"';

	echo '<br />';

	// SizeOfCode
	$size_of_code = $byte->getReadBytes(4);
	$size_of_code = $byte->getLittleEndian($size_of_code);
	$size_of_code = hexdec($size_of_code);
	echo '모든 코드 섹션의 사이즈를 합한 크기 = "';
	echo $size_of_code;
	echo '"';

	echo '<br />';

	// SizeOfInitializedData
	$size_of_initialized_data = $byte->getReadBytes(4);
	$size_of_initialized_data = $byte->getLittleEndian($size_of_initialized_data);
	$size_of_initialized_data = hexdec($size_of_initialized_data);
	echo '초기화된 데이터 섹션의 전체 크기 (코드섹션 제외) = "';
	echo $size_of_initialized_data;
	echo '"';

	echo '<br />';

	// SizeOfUnInitializedData
	$size_of_uninitialized_data = $byte->getReadBytes(4);
	$size_of_uninitialized_data = $byte->getLittleEndian($size_of_uninitialized_data);
	$size_of_uninitialized_data = hexdec($size_of_uninitialized_data);
	echo '초기화되지 않은 데이터 섹션의 바이트 수 = "';
	echo $size_of_uninitialized_data;
	echo '"';

	echo '<br />';

	// AddressOfEntryPoint
	$address_of_entry_point = $byte->getReadBytes(4);
	$address_of_entry_point = $byte->getLittleEndian($address_of_entry_point);
	echo '프로그램의 시작 주소 (상대 주소 RVA) (Entry Point) = "';
	echo $address_of_entry_point;
	echo '"';

	echo '<br />';

	// BaseOfCode
	$base_of_code = $byte->getReadBytes(4);
	$base_of_code = $byte->getLittleEndian($base_of_code);
	echo '코드섹션의 첫 번째 바이트에 대한 RVA = "';
	echo $base_of_code;
	echo '"';

	echo '<br />';

	// PE32+ HEADER 에서는 존재하지 않음
	if (PE_ADDR_SIZE == 4)
	{
		// PE32 HEADER에서만 출력

		// BaseOfData
		$base_of_data = $byte->getReadBytes(4);
		$base_of_data = $byte->getLittleEndian($base_of_data);
		echo '데이터 섹션(.data) 시작주소에 대한 RVA = "';
		echo $base_of_data;
		echo '" ; 32Bit PE 전용';

		echo '<br />';
	}

	// ImageBase
	$image_base = $byte->getReadBytes(PE_ADDR_SIZE);
	$image_base = $byte->getLittleEndian($image_base);
	echo 'PE 메모리에 매핑될 메모리상의 시작주소 (ImageBase) = "';
	echo $image_base;
	echo '"';

	echo '<br />';

	// SectionAlignment
	$section_alignment = $byte->getReadBytes(4);
	$section_alignment = $byte->getLittleEndian($section_alignment);
	echo '각 섹션의 배치 간격 (각 섹션의 시작주소는 이값의 배수) = "';
	echo $section_alignment;
	echo '"';

	echo '<br />';

	// FileAlignment
	$file_alignment = $byte->getReadBytes(4);
	$file_alignment = $byte->getLittleEndian($file_alignment);
	echo '각각의 섹션을 구성하는 바이너리 데이터들의 시작주소의 간격 = "';
	echo $file_alignment;
	echo '"';

	echo '<br />';

	// MajorOperationgSystemVersion
	$major_operationg_system_version = $byte->getReadBytes(2);
	$major_operationg_system_version = $byte->getLittleEndian($major_operationg_system_version);
	echo '해당 PE파일을 실행하는 데 필요한 운영체제의 최소 버전 = "';
	echo $major_operationg_system_version;
	echo '"';

	echo '<br />';

	// MinorOperationgSystemVersion
	$minor_operationg_system_version = $byte->getReadBytes(2);
	$minor_operationg_system_version = $byte->getLittleEndian($minor_operationg_system_version);
	echo '해당 PE파일을 실행하는 데 필요한 운영체제의 최소 버전 = "';
	echo $minor_operationg_system_version;
	echo '"';

	echo '<br />';

	// MajorImageVersion
	$major_image_version = $byte->getReadBytes(2);
	$major_image_version = $byte->getLittleEndian($major_image_version);
	echo '유저가 임의로 정하는 EXE나 DLL 버전 = "';
	echo $major_image_version;
	echo '"';

	echo '<br />';

	// MinorImageVersion
	$minor_image_version = $byte->getReadBytes(2);
	$minor_image_version = $byte->getLittleEndian($minor_image_version);
	echo '유저가 임의로 정하는 EXE나 DLL 버전 = "';
	echo $minor_image_version;
	echo '"';

	echo '<br />';

	// MajorSubsystemVersion
	$major_subsystem_version = $byte->getReadBytes(2);
	$major_subsystem_version = $byte->getLittleEndian($major_subsystem_version);
	echo '해당 PE를 실행하는데 필요한 서브 시스템의 최소버전 = "';
	echo $major_subsystem_version;
	echo '"';

	echo '<br />';

	// MinorSubsystemVersion
	$minor_subsystem_version = $byte->getReadBytes(2);
	$minor_subsystem_version = $byte->getLittleEndian($minor_subsystem_version);
	echo '해당 PE를 실행하는데 필요한 서브 시스템의 최소버전 = "';
	echo $minor_subsystem_version;
	echo '"';

	echo '<br />';

	// Win32Version
	$win32_version = $byte->getReadBytes(4);
	$win32_version = $byte->getLittleEndian($win32_version);
	echo 'WIN32 버전 = "';
	echo $win32_version;
	echo '"';

	echo '<br />';

	// SizeOfImage
	$size_of_image = $byte->getReadBytes(4);
	$size_of_image = $byte->getLittleEndian($size_of_image);
	$size_of_image = hexdec($size_of_image);
	echo '로더가 PE를 메모리상에 로드할 때 확보해야할 충분한 크기 = "';
	echo $size_of_image;
	echo '"';

	echo '<br />';

	// SizeOfHeader
	$size_of_header = $byte->getReadBytes(4);
	$size_of_header = $byte->getLittleEndian($size_of_header);
	$size_of_header = hexdec($size_of_header);
	echo 'MS-DOS헤더, PE헤더, 섹션테이블의 크기를 합친 바이트 수 = "';
	echo $size_of_header;
	echo '"';

	echo '<br />';

	// CheckSum
	$check_sum = $byte->getReadBytes(4);
	$check_sum = $byte->getLittleEndian($check_sum);
	echo '이미지의 체크섬 값 (설정안됨 : 0) = "';
	echo $check_sum;
	echo '"';

	echo '<br />';

	// Subsystem
	$subsystem = $byte->getReadBytes(2);
	$subsystem = $byte->getLittleEndian($subsystem);
	$subsystem = hexdec($subsystem);
	echo '유저 인터페이스로 사용하는 서브시스템의 종류 = "';
	echo $subsystem;
	echo '" ; ';
	if ($subsystem === 0) echo 'IMAGE_SUBSYSTEM_UNKNOWN';
	if ($subsystem === 1) echo 'IMAGE_SUBSYSTEM_NATIVE';
	if ($subsystem === 2) echo 'IMAGE_SUBSYSTEM_WINDOWS_GUI';
	if ($subsystem === 3) echo 'IMAGE_SUBSYSTEM_WINDOWS_CUI';
	if ($subsystem === 5) echo 'IMAGE_SUBSYSTEM_OS2_CUI';
	if ($subsystem === 7) echo 'IMAGE_SUBSYSTEM_POSIX_CUI';
	if ($subsystem === 8) echo 'IMAGE_SUBSYSTEM_NATIVE_WINDOWS';
	if ($subsystem === 9) echo 'IMAGE_SUBSYSTEM_WINDOWS_CE_GUI';

	echo '<br />';

	// DllCharacteristics
	$dll_characteristics = $byte->getReadBytes(2);
	$dll_characteristics = $byte->getLittleEndian($dll_characteristics);
	echo 'DLL초기화함수가 호출되어야 하는지에 대한 지시 플래그 = "';
	echo $dll_characteristics;
	echo '"';

	echo '<br />';

	// SizeOfStackReserve
	$size_of_stack_reserve = $byte->getReadBytes(PE_ADDR_SIZE);
	$size_of_stack_reserve = $byte->getLittleEndian($size_of_stack_reserve);
	echo 'PE가 메모리에 로드될때 시스템이 디폴트 스택을 만들어주기 위해 참조하는 값 = "';
	echo $size_of_stack_reserve;
	echo '"';

	echo '<br />';

	// SizeOfStackCommit
	$size_of_stack_commit = $byte->getReadBytes(PE_ADDR_SIZE);
	$size_of_stack_commit = $byte->getLittleEndian($size_of_stack_commit);
	echo 'PE가 메모리에 로드될때 시스템이 디폴트 스택을 만들어주기 위해 참조하는 값 = "';
	echo $size_of_stack_commit;
	echo '"';

	echo '<br />';

	// SizeOfHeapReserve
	$size_of_heap_reserve = $byte->getReadBytes(PE_ADDR_SIZE);
	$size_of_heap_reserve = $byte->getLittleEndian($size_of_heap_reserve);
	echo 'PE가 메모리에 로드될때 시스템이 디폴트 힙을 만들어주기 위해 참조하는 값 = "';
	echo $size_of_heap_reserve;
	echo '"';

	echo '<br />';

	// SizeOfHeapCommit
	$size_of_heap_commit = $byte->getReadBytes(PE_ADDR_SIZE);
	$size_of_heap_commit = $byte->getLittleEndian($size_of_heap_commit);
	echo 'PE가 메모리에 로드될때 시스템이 디폴트 힙을 만들어주기 위해 참조하는 값 = "';
	echo $size_of_heap_commit;
	echo '"';

	echo '<br />';

	// LoaderFlags
	$loader_flags = $byte->getReadBytes(4);
	$loader_flags = $byte->getLittleEndian($loader_flags);
	echo 'LoaderFlags (0 값으로 셋팅) = "';
	echo $loader_flags;
	echo '"';

	echo '<br />';

	// NumberOfRvaAndSizes
	$number_of_rva_and_sizes = $byte->getReadBytes(4);
	$number_of_rva_and_sizes = $byte->getLittleEndian($number_of_rva_and_sizes);
	$number_of_rva_and_sizes = hexdec($number_of_rva_and_sizes);
	echo 'IMAGE_DATA_DIRECTORY 배열의 원소 개수 (항상 16개) = "';
	echo $number_of_rva_and_sizes;
	echo '"';

	echo '<h3>IMAGE_DATA_DIRECTORY</h3>';

	echo '<h4>IMAGE_DIRECTORY_ENTRY_EXPORT</h4>';
	// ExportTableAddress
	$export_table_address = $byte->getReadBytes(4);
	$export_table_address = $byte->getLittleEndian($export_table_address);
	echo 'Export Table Address = "';
	echo $export_table_address;
	echo '"';

	echo '<br />';

	// ExportTableSize
	$export_table_size = $byte->getReadBytes(4);
	$export_table_size = $byte->getLittleEndian($export_table_size);
	$export_table_size = hexdec($export_table_size);
	echo 'Export Table Size = "';
	echo $export_table_size;
	echo '"';

	echo '<h4>IMAGE_DIRECTORY_ENTRY_IMPORT</h4>';
	// ImportTableAddress
	$import_table_address = $byte->getReadBytes(4);
	$import_table_address = $byte->getLittleEndian($import_table_address);
	echo 'Import Table Address = "';
	echo $import_table_address;
	echo '"';

	echo '<br />';

	// ImportTableSize
	$import_table_size = $byte->getReadBytes(4);
	$import_table_size = $byte->getLittleEndian($import_table_size);
	$import_table_size = hexdec($import_table_size);
	echo 'Import Table Size = "';
	echo $import_table_size;
	echo '"';

	echo '<h4>IMAGE_DIRECTORY_ENTRY_RESOURCE</h4>';
	// ResourceTableAddress
	$resource_table_address = $byte->getReadBytes(4);
	$resource_table_address = $byte->getLittleEndian($resource_table_address);
	echo 'Resource Table Address = "';
	echo $resource_table_address;
	echo '"';

	echo '<br />';

	// ResourceTableSize
	$resource_table_size = $byte->getReadBytes(4);
	$resource_table_size = $byte->getLittleEndian($resource_table_size);
	$resource_table_size = hexdec($resource_table_size);
	echo 'Resource Table Size = "';
	echo $resource_table_size;
	echo '"';

	echo '<h4>IMAGE_DIRECTORY_ENTRY_EXCEPTION</h4>';
	// ExceptionTableAddress
	$exception_table_address = $byte->getReadBytes(4);
	$exception_table_address = $byte->getLittleEndian($exception_table_address);
	echo 'Exception Table Address = "';
	echo $exception_table_address;
	echo '"';

	echo '<br />';

	// ResourceTableSize
	$exception_table_size = $byte->getReadBytes(4);
	$exception_table_size = $byte->getLittleEndian($exception_table_size);
	$exception_table_size = hexdec($exception_table_size);
	echo 'Exception Table Size = "';
	echo $exception_table_size;
	echo '"';

	// WIN_CERTIFICATE 구조체들의 리스트의 시작 번지
	echo '<h4>IMAGE_DIRECTORY_ENTRY_SECURITY</h4>';
	// Certificate File Pointer
	$certificate_file_pointer = $byte->getReadBytes(4);
	$certificate_file_pointer = $byte->getLittleEndian($certificate_file_pointer);
	echo 'Certificate File Pointer = "';
	echo $certificate_file_pointer;
	echo '"';

	echo '<br />';

	// Certificate Table Size
	$certificate_table_size = $byte->getReadBytes(4);
	$certificate_table_size = $byte->getLittleEndian($certificate_table_size);
	$certificate_table_size = hexdec($certificate_table_size);
	echo 'Certificate Table Size = "';
	echo $certificate_table_size;
	echo '"';

	// 기준 재배치 정보
	// ImageBase 필드에 지정된 가상 주소 공간의 주소에 위치시키지 못했을 때 코드 상의
	// 포인터 연산과 관련된 주소정보를 다시 갱신해야 하는 경우 필요한 재배치 정보
	echo '<h4>IMAGE_DIRECTORY_ENTRY_BASERELOC</h4>';
	// Relocation Table Address
	$relocation_table_address = $byte->getReadBytes(4);
	$relocation_table_address = $byte->getLittleEndian($relocation_table_address);
	echo 'Relocation Table Address = "';
	echo $relocation_table_address;
	echo '"';

	echo '<br />';

	// Relocation Table Size
	$relocation_table_size = $byte->getReadBytes(4);
	$relocation_table_size = $byte->getLittleEndian($relocation_table_size);
	$relocation_table_size = hexdec($relocation_table_size);
	echo 'Relocation Table Size = "';
	echo $relocation_table_size;
	echo '"';

	// IMAGE_DEBUG_DIRECTORY 구조체의 배열을 가리키는 번지
	// 각각 해당 이미지의 디버그 정보를 기술 한다.
	echo '<h4>IMAGE_DIRECTORY_ENTRY_DEBUG</h4>';
	// Debug Data Address
	$debug_data_address = $byte->getReadBytes(4);
	$debug_data_address = $byte->getLittleEndian($debug_data_address);
	echo 'Debug Data Address = "';
	echo $debug_data_address;
	echo '"';

	echo '<br />';

	// Debug Data Size
	$debug_data_size = $byte->getReadBytes(4);
	$debug_data_size = $byte->getLittleEndian($debug_data_size);
	$debug_data_size = hexdec($debug_data_size);
	echo 'Debug Data Size = "';
	echo $debug_data_size;
	echo '"';

	// 아키텍처에 구체적인 데이터 구조체의 배열에 대한 포인터
	// x86 및 IA-64 계열에서는 거의 사용되지 않는다.
	echo '<h4>IMAGE_DIRECTORY_ENTRY_ARCHITECTURE</h4>';
	// Architecture Data Address
	$architecture_data_address = $byte->getReadBytes(4);
	$architecture_data_address = $byte->getLittleEndian($architecture_data_address);
	echo 'Architecture Data Address = "';
	echo $architecture_data_address;
	echo '"';

	echo '<br />';

	// Architecture Data Size
	$architecture_data_size = $byte->getReadBytes(4);
	$architecture_data_size = $byte->getLittleEndian($architecture_data_size);
	$architecture_data_size = hexdec($architecture_data_size);
	echo 'Architecture Data Size = "';
	echo $architecture_data_size;
	echo '"';

	// 글로버 포인터(GP)로 사용되는 RVA i386 계열은 사용안함, ia-64에서는 사용
	echo '<h4>IMAGE_DIRECTORY_ENTRY_GLOBALPTR</h4>';
	// Global Ptr Address
	$global_ptr_address = $byte->getReadBytes(4);
	$global_ptr_address = $byte->getLittleEndian($global_ptr_address);
	echo 'Global Ptr Address = "';
	echo $global_ptr_address;
	echo '"';

	echo '<br />';

	// Reserved
	$reserved = $byte->getReadBytes(4);
	$reserved = $byte->getLittleEndian($reserved);
	echo 'Reserved = "';
	echo $reserved;
	echo '"';

	// 스레드 지역 저장소(Thread Local Storage)의 초기화 섹션에 대한 포인터
	// 별도의 TLS 함수 없이 __declspec(thread) 지시어로 변수가 선언되면 TLS에 들어가며
	// 이를 위해 링커는 별도의 TLS 섹션을 만든다
	// 이 엔트리의 VirtualAddress 는 TLS 섹션을 가리키는 RVA 가 된다.
	echo '<h4>IMAGE_DIRECTORY_ENTRY_TLS</h4>';
	// TLS Table Address
	$tls_table_address = $byte->getReadBytes(4);
	$tls_table_address = $byte->getLittleEndian($tls_table_address);
	echo 'TLS Table Address = "';
	echo $tls_table_address;
	echo '"';

	echo '<br />';

	// TLS Table Size
	$tls_table_size = $byte->getReadBytes(4);
	$tls_table_size = $byte->getLittleEndian($tls_table_size);
	$tls_table_size = hexdec($tls_table_size);
	echo 'TLS Table Size = "';
	echo $tls_table_size;
	echo '"';
	
	// IMAGE_LOAD_CONFIG_DIRECTORY 구조체에 대한 포인터
	echo '<h4>IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG</h4>';
	// Load Config Table Address
	$load_config_table_address = $byte->getReadBytes(4);
	$load_config_table_address = $byte->getLittleEndian($load_config_table_address);
	echo 'Load Config Table Address = "';
	echo $load_config_table_address;
	echo '"';

	echo '<br />';

	// Load Config Table Size
	$load_config_table_size = $byte->getReadBytes(4);
	$load_config_table_size = $byte->getLittleEndian($load_config_table_size);
	$load_config_table_size = hexdec($load_config_table_size);
	echo 'Load Config Table Size = "';
	echo $load_config_table_size;
	echo '"';
	
	// 바인딩과 관련된 정보를 담고 있다.
	echo '<h4>IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT</h4>';
	// Bound Import Table Address
	$bound_import_table_address = $byte->getReadBytes(4);
	$bound_import_table_address = $byte->getLittleEndian($bound_import_table_address);
	echo 'Bound Import Table Address = "';
	echo $bound_import_table_address;
	echo '"';

	echo '<br />';

	// Bound Import Table Size
	$bound_import_table_size = $byte->getReadBytes(4);
	$bound_import_table_size = $byte->getLittleEndian($bound_import_table_size);
	$bound_import_table_size = hexdec($bound_import_table_size);
	echo 'Bound Import Table Size = "';
	echo $bound_import_table_size;
	echo '"';
	
	// 첫 번째 임포트 주소 테이블(IAT)의 시작 번지를 가리킨다.
	// 임포트된 각각의 DLL에 대한 IAT는 메모리 상에서 연속적으로 나타난다.
	// Size 필드는 모든 IAT의 전체 크기를 가리킨다.
	echo '<h4>IMAGE_DIRECTORY_ENTRY_IAT</h4>';
	// Import Address Table Address
	$import_address_table_address = $byte->getReadBytes(4);
	$import_address_table_address = $byte->getLittleEndian($import_address_table_address);
	echo 'Import Address Table Address = "';
	echo $import_address_table_address;
	echo '"';

	echo '<br />';

	// Import Address Table Size
	$import_address_table_size = $byte->getReadBytes(4);
	$import_address_table_size = $byte->getLittleEndian($import_address_table_size);
	$import_address_table_size = hexdec($import_address_table_size);
	echo 'Import Address Table Size = "';
	echo $import_address_table_size;
	echo '"';

	// 지연 로딩 정보에 대한 포인터
	// 지연 로딩 DLL은 해당 API가 처음으로 호출되기 전까지는 로드되지 않는다.
	// 지연 로딩 DLL에대한 그 어떠한 정보도 윈도우는 갖고있지 않다.
	echo '<h4>IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT</h4>';
	// Delay Import Descriptor Address
	$delay_impory_descriptor_address = $byte->getReadBytes(4);
	$delay_impory_descriptor_address = $byte->getLittleEndian($delay_impory_descriptor_address);
	echo 'Delay Import Descriptor Address = "';
	echo $delay_impory_descriptor_address;
	echo '"';

	echo '<br />';

	// Delay Import Descriptor Size
	$delay_impory_descriptor_size = $byte->getReadBytes(4);
	$delay_impory_descriptor_size = $byte->getLittleEndian($delay_impory_descriptor_size);
	$delay_impory_descriptor_size = hexdec($delay_impory_descriptor_size);
	echo 'Delay Import Descriptor Size = "';
	echo $delay_impory_descriptor_size;
	echo '"';

	// .NET 응용 애플리케이션이나 DLL용 PE를 위한 부분
	// PE 내의 .NET정보에 대한 최상위 정보의 시작번지를 가리킨다.
	// IMAGE_COR20_HEADER 구조체의 형태로 구성됨
	echo '<h4>IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR</h4>';
	// COM+ Runtime Header Address
	$com_runtime_header_address = $byte->getReadBytes(4);
	$com_runtime_header_address = $byte->getLittleEndian($com_runtime_header_address);
	echo 'COM+ Runtime Header Address = "';
	echo $com_runtime_header_address;
	echo '"';

	echo '<br />';

	// Import Address Table Size
	$import_address_table_size = $byte->getReadBytes(4);
	$import_address_table_size = $byte->getLittleEndian($import_address_table_size);
	$import_address_table_size = hexdec($import_address_table_size);
	echo 'Import Address Table Size = "';
	echo $import_address_table_size;
	echo '"';

	echo '<br />';

	// Reserved
	$reserved = $byte->getReadBytes(4);
	$reserved = $byte->getLittleEndian($reserved);
	echo 'Reserved = "';
	echo $reserved;
	echo '"';

	echo '<br />';

	// Reserved
	$reserved = $byte->getReadBytes(4);
	$reserved = $byte->getLittleEndian($reserved);
	echo 'Reserved = "';
	echo $reserved;
	echo '"';

	// 해당 섹션에 대한 구조체 위치정보 저장용 변수
	// RVA to RAW
	$section_array = array();
	// PE Header 의 다음 40Byte로 구성됨
	for ($k = 0; $k < $number_of_sections; $k++)
	{
		// 섹션 정보 저장용 변수 초기화
		$section_array[$k] = null;

		echo '<h3>IMAGE_SECTION_HEADER</h3>';
		// Name
		$name = '';
		$null = array();
		for ($i = 0; $i < 8; $i++)
		{
			$byte_data = hexdec($byte->getReadBytes(1));
			if ($byte_data != 0x00)
				$name .= chr($byte_data);
			else
				$null[] = 0x00;
		}
		echo 'Name (섹션이름 값) = "';
		if ($name == '')
		{
			echo '<span style="color:#f00;"><b>Error : Unknown IMAGE_SECTION_HEADER!!</b></span>"<br />';
			echo '"<span style="color:#f00;">해당 섹션의 데이터가 올바르지 않거나 손상 / 특정 프로그램에 의해 암호화 되었을 수 있습니다.</span>';
		}
		else
		{
			echo $name;
			if (count($null) > 0) echo ', '.implode(', ', $null);
		}
		echo '"';
		// 섹션 이름 저장
		$section_array[$k]->Name = $name;

		echo '<br />';

		// obj file : PhysicalAddress / pe file : VirtualSize
		$virtual_size = $byte->getReadBytes(4);
		$virtual_size = $byte->getLittleEndian($virtual_size);
		$virtual_size = hexdec($virtual_size);
		echo 'Virtual Size (PE로더에 의해 메모리에 올려진 후에 해당 섹션이 얼마만큼의 크기를 가지는지에 대한 정보) = "';
		echo $virtual_size;
		echo '"';
		// 메모리에서 해당 섹션이 차지하는 크기
		$section_array[$k]->VirtualSize = $virtual_size;

		echo '<br />';

		// VirtualAddress
		$virtual_address = $byte->getReadBytes(4);
		$virtual_address = $byte->getLittleEndian($virtual_address);
		echo 'Virtual Address (PE에서 해당 섹션이 가상주소공간에 매핑되었을때 RVA값) = "';
		echo $virtual_address;
		echo '"';
		// 메모리에서 섹션의 시작 주소 (RVA)
		$section_array[$k]->VirtualAddress = $virtual_address;

		echo '<br />';

		// SizeOfRawData
		$size_of_raw_data = $byte->getReadBytes(4);
		$size_of_raw_data = $byte->getLittleEndian($size_of_raw_data);
		$size_of_raw_data = hexdec($size_of_raw_data);
		echo 'RawData상에서 해당 섹션에 대한 실제 사용된 크기의 정보 = "';
		echo $size_of_raw_data;
		echo '"';
		// 파일에서 섹션이 차지하는 크기
		$section_array[$k]->SizeOfRawData = $size_of_raw_data;

		echo '<br />';

		// PointerToRawData
		$pointer_to_raw_data = $byte->getReadBytes(4);
		$pointer_to_raw_data = $byte->getLittleEndian($pointer_to_raw_data);
		echo 'PointerToRawData (PE파일상에서의 선두로부터의 오프셋) = "';
		echo $pointer_to_raw_data;
		echo '"';
		// 파일에서 섹션의 시작 위치
		$section_array[$k]->PointerToRawData = $pointer_to_raw_data;

		echo '<br />';

		// PointerToRelocations
		$pointer_to_relocations = $byte->getReadBytes(4);
		$pointer_to_relocations = $byte->getLittleEndian($pointer_to_relocations);
		echo 'OBJ 파일에서만 사용하는 해당 섹션 재배치 오프셋 = "';
		echo $pointer_to_relocations;
		echo '"';

		echo '<br />';

		// PointerToLinenumbers
		$pointer_to_linenumbers = $byte->getReadBytes(4);
		$pointer_to_linenumbers = $byte->getLittleEndian($pointer_to_linenumbers);
		$pointer_to_linenumbers = hexdec($pointer_to_linenumbers);
		echo 'PE에 첨부되었을 경우의 (Common Object File Format) 라인번호 = "';
		echo $pointer_to_linenumbers;
		echo '"';

		echo '<br />';

		// NumberOfRelocations
		$number_of_relocations = $byte->getReadBytes(2);
		$number_of_relocations = $byte->getLittleEndian($number_of_relocations);
		$number_of_relocations = hexdec($number_of_relocations);
		echo 'PointerToRelocations 가 가리키는 IMAGE_RELOCATION 구조체 배열의 원소의 개수 = "';
		echo $number_of_relocations;
		echo '"';

		echo '<br />';

		// NumberOfLinenumbers
		$number_of_linenumbers = $byte->getReadBytes(2);
		$number_of_linenumbers = $byte->getLittleEndian($number_of_linenumbers);
		$number_of_linenumbers = hexdec($number_of_linenumbers);
		echo 'PointerToLinenumbers 가 가리키는 IMAGE_LINENUMBER 구조체 배열의 원소의 개수 = "';
		echo $number_of_linenumbers;
		echo '"';

		echo '<br />';

		// Characteristics
		$characteristics = $byte->getReadBytes(4);
		$characteristics = $byte->getLittleEndian($characteristics);
		$characteristics = hexdec($characteristics);
		echo '해당 섹션의 속성 플래그의 집합 = "';
		echo $characteristics;
		echo '" ; ';
		$characteristics_array = array();
		if ($characteristics & 0x00000020) $characteristics_array[] = 'IMAGE_SCN_CNT_CODE';
		if ($characteristics & 0x00000040) $characteristics_array[] = 'IMAGE_SCN_CNT_INITIALIZED_DATA';
		if ($characteristics & 0x00000080) $characteristics_array[] = 'IMAGE_SCN_CNT_UNINITIALIZED_DATA';
		if ($characteristics & 0x02000000) $characteristics_array[] = 'IMAGE_SCN_MEM_DISCARDABLE';
		if ($characteristics & 0x04000000) $characteristics_array[] = 'IMAGE_SCN_MEM_NOT_CACHED';
		if ($characteristics & 0x08000000) $characteristics_array[] = 'IMAGE_SCN_MEM_NOT_PAGED';
		if ($characteristics & 0x10000000) $characteristics_array[] = 'IMAGE_SCN_MEM_SHARED';
		if ($characteristics & 0x20000000) $characteristics_array[] = 'IMAGE_SCN_MEM_EXECUTE';
		if ($characteristics & 0x40000000) $characteristics_array[] = 'IMAGE_SCN_MEM_READ';
		if ($characteristics & 0x80000000) $characteristics_array[] = 'IMAGE_SCN_MEM_WRITE';
		echo implode('<b> | </b>', $characteristics_array);
		// 섹션의 특징
		$section_array[$k]->Characteristics = array($characteristics, $characteristics_array);
	}

	echo '<h3>IMAGE_EXPORT_DIRECTORY</h3>';

	$export_table_memory_address = sprintf('0x%08x', $image_base + $export_table_address);
	// 실제 메모리상에 위치하게 되는 Export Directory 구조체의 메모리 주소
	echo 'Export_Directory_Address : '.$export_table_memory_address;
	echo '<br /><br />';

	// IMAGE_EXPORT_DIRECTORY 정보 구하기
	for ($i = 0; $i < $number_of_sections; $i++)
	{
		// 해당 섹션의 정보 구하기
		// 해당 섹션의 영역위치와 크기 구하기
		// 파일에서 시작되는 위치
		$start_file_address = $section_array[$i]->PointerToRawData;
		// 파일에서 끝나는 위치
		$end_file_address = $start_file_address + $section_array[$i]->SizeOfRawData;
		// 주소값 형식으로 변환
		$end_file_address = sprintf("0x%08x", $end_file_address);
		// 메모리 상에서 시작되는 위치
		$start_memory_address = sprintf('0x%08x', $image_base + $section_array[$i]->VirtualAddress);
		// 메모리 상에서 종료되는 위치
		$end_memory_address = sprintf('0x%08x', $start_memory_address + $section_array[$i]->VirtualSize);

		// 위치한 섹션을 찾았을 경우
		if ($export_table_memory_address >= $start_memory_address && $export_table_memory_address <= $end_memory_address)
		{
			// 관련 정보 출력
			echo 'Section Name : '.$section_array[$i]->Name.'<br />';
			echo 'Section File Start Address : '.$start_file_address.'<br />';
			echo 'Section File End Address : '.$end_file_address.'<br />';
			echo 'Section Memory Start Address : '.$start_memory_address.'<br />';
			echo 'Section Memory End Address : '.$end_memory_address.'<br /><br />';

			// RVA to RAW 수행
			$raw_file_offset = $export_table_address - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
			$raw_file_offset = sprintf("0x%08x", $raw_file_offset);
			// 관련 정보 출력 시작
			echo 'RVA to RAW : '.$export_table_address.' => '.$raw_file_offset.'<br />';
			echo '<br />';

			// 구한 file_offset 으로 이동
			$byte->setPointer($raw_file_offset);
			// Characteristics
			$characteristics = $byte->getReadBytes(4);
			$characteristics = $byte->getLittleEndian($characteristics);
			$characteristics = hexdec($characteristics);
			echo 'Characteristics = "';
			echo $characteristics;
			echo '"';

			echo '<br />';

			// TimeDateStamp
			$time_date_stamp = $byte->getReadBytes(4);
			$time_date_stamp = $byte->getLittleEndian($time_date_stamp);
			echo 'TimeDateStamp = "';
			echo $time_date_stamp;
			echo '" ; ';
			echo gmdate('Y.m.d H:i:s', hexdec($time_date_stamp));

			echo '<br />';

			// MajorVersion
			$major_version = $byte->getReadBytes(2);
			$major_version = $byte->getLittleEndian($major_version);
			echo 'MajorVersion = "';
			echo $major_version;
			echo '"';

			echo '<br />';

			// MinorVersion
			$minor_version = $byte->getReadBytes(2);
			$minor_version = $byte->getLittleEndian($minor_version);
			echo 'MinorVersion = "';
			echo $minor_version;
			echo '"';

			echo '<br />';

			// NameAddress
			$name_address = $byte->getReadBytes(4);
			$name_address = $byte->getLittleEndian($name_address);
			echo 'Name Address = "';
			echo $name_address;
			echo '" ; <b>';
			// Name Address To RAW
			$name_address_raw_offset = $name_address - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
			$word = 0xff;
			$export_name = '';
			// NULL 문자를 발견 할 때 까지 함수이름 설정
			while ($word != "\0")
			{
				$word = $byte->binToAscii($byte->getBytes($name_address_raw_offset++, 1));
				// 함수 이름 셋팅
				$export_name .= $word;
			}
			echo $export_name;
			echo '</b>';

			echo '<br />';

			// Base
			$base = $byte->getReadBytes(4);
			$base = $byte->getLittleEndian($base);
			echo 'Base = "';
			echo $base;
			echo '"';

			echo '<br />';

			// NumberOfFunctions
			$nubmer_of_functions = $byte->getReadBytes(4);
			$nubmer_of_functions = $byte->getLittleEndian($nubmer_of_functions);
			echo '실제 EXPORT 함수 개수 (NumberOfFunctions) = "';
			echo $nubmer_of_functions;
			echo '"';

			echo '<br />';

			// NumberOfNames
			$number_of_names = $byte->getReadBytes(4);
			$number_of_names = $byte->getLittleEndian($number_of_names);
			echo 'EXPORT 함수중에서 이름을 가지는 함수 개수 (NumberOfNames) = "';
			echo $number_of_names;
			echo '"';

			echo '<br />';

			// AddressOfFunctions
			$address_of_functions = $byte->getReadBytes(4);
			$address_of_functions = $byte->getLittleEndian($address_of_functions);
			echo 'EXPORT 함수들의 시작 위치 배열의 주소 (AddressOfFunctions) = "';
			echo $address_of_functions;
			echo '"';

			echo '<br />';

			// AddressOfNames
			$address_of_names = $byte->getReadBytes(4);
			$address_of_names = $byte->getLittleEndian($address_of_names);
			echo '함수 이름 배열의 주소 (AddressOfNames) = "';
			echo $address_of_names;
			echo '"';

			echo '<br />';

			// AddressOfNameOrdinals
			$address_of_name_ordinals = $byte->getReadBytes(4);
			$address_of_name_ordinals = $byte->getLittleEndian($address_of_name_ordinals);
			echo 'ORDINAL 배열의 주소 (AddressOfNameOrdinals) = "';
			echo $address_of_name_ordinals;
			echo '"';

			echo '<br />';

			// Name 값 얻어오기
			// RVA to RAW 수행
			$name_raw_file_offset = $name_address - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
			// Name 구하기
			//$ext_name = $byte->getBytes($name_raw_file_offset, hexdec($number_of_names));
			echo '<br />';
			//echo $byte->binToAscii($ext_name).'<br />';

			// 함수들 목록 구해오기
			// RVA to RAW 수행
			$address_name_raw_file_offset = $address_of_names - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
			// EAT RVA Table
			$eat_rva_array = array();

			// 함수들의 주소 구해오기
			// ordinal index 값 구하기
			$address_ordinals_raw_file_offset = $address_of_name_ordinals - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
			// address of function 구하기
			$address_functions_raw_file_offset = $address_of_functions - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
			// EAT Address Table
			$eat_ordinals_array = array();
			$eat_addr_array = array();
			for ($j = 0; $j < $number_of_names; $j++)
			{
				$eat_rva_array[$j] = $byte->getBytes($address_name_raw_file_offset+($j*4), 4);
				$eat_rva_array[$j] = $byte->getLittleEndian($eat_rva_array[$j]);
				// 함수의 이름이 저장되어 있는 파일의 RVA
				//echo 'EXT RVA['.$j.'] = '.$eat_rva_array[$j];
				// 함수 이름 구하기
				// RVA to RAW 수행
				$eat_raw = $eat_rva_array[$j] - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;

				$word = 0xff;
				$eat_function_name = '';
				// NULL 문자를 발견 할 때 까지 함수이름 설정
				while ($word != "\0")
				{
					$word = $byte->binToAscii($byte->getBytes($eat_raw++, 1));
					// 함수 이름 셋팅
					$eat_function_name .= $word;
				}
				// 멩글링된 함수의 이름을 정상적인 함수의 이름으로 바꾸어 출력한다.
				$undname = $eat_function_name;
				$byteStr = new ByteString($undname);
				// 멩글링 여부를 확인
				if ($byteStr->getBytes(0, 1) == '?')
				{
					echo 'UNDNAME : <b>'.$undname.'</b>';
					echo '<br />';
				}
				else
				{
					// 맹글링 되어있지 않은 경우 진하게 설정
					$eat_function_name = '<b>'.$eat_function_name.'</b>';
				}
				// 구한 함수의 이름을 출력
				//echo '<br />';
				echo 'ASCII "'.$eat_function_name.'"';
				echo '<br />';

				// 함수의 시작 주소부분 구하기
				$eat_ordinals_array[$j] = $byte->getBytes($address_ordinals_raw_file_offset+($j*2), 2);
				$eat_ordinals_array[$j] = $byte->getLittleEndian($eat_ordinals_array[$j]);
				$eat_ordinals_array[$j] = hexdec($eat_ordinals_array[$j]);
				// 본래 주소값 구하기
				$eat_addr_array[$j] = $byte->getBytes($address_functions_raw_file_offset+($eat_ordinals_array[$j]*4), 4);
				$eat_addr_array[$j] = $byte->getLittleEndian($eat_addr_array[$j]);

				// 아래의 소스를 주석처리 할 경우 ImageBase 를 더하지 않은 값
				// ImageBase 를 더한값
				//$eat_addr_array[$j] = sprintf('0x%08x', $image_base + $eat_addr_array[$j]);
				echo 'EXT Function Address['.$j.'] = '.$eat_addr_array[$j];
				//echo '<br />';
				//echo 'EXT Ordinals['.$j.'] = '.$eat_ordinals_array[$j];
				
				echo '<br /><br />';
			}
		}
	}

	echo '<h3>IMAGE_IMPORT_DIRECTORY</h3>';

	$import_table_memory_address = sprintf('0x%08x', $image_base + $import_table_address);
	// 실제 메모리상에 위치하게 되는 Import Directory 구조체의 메모리 주소
	echo 'Import_Directory_Address : '.$import_table_memory_address;
	echo '<br /><br />';

	// IMAGE_IMPORT_DIRECTORY 정보 구하기
	for ($i = 0; $i < $number_of_sections; $i++)
	{
		// 해당 섹션의 정보 구하기
		// 해당 섹션의 영역위치와 크기 구하기
		// 파일에서 시작되는 위치
		$start_file_address = $section_array[$i]->PointerToRawData;
		// 파일에서 끝나는 위치
		$end_file_address = $start_file_address + $section_array[$i]->SizeOfRawData;
		// 주소값 형식으로 변환
		$end_file_address = sprintf("0x%08x", $end_file_address);
		// 메모리 상에서 시작되는 위치
		$start_memory_address = sprintf('0x%08x', $image_base + $section_array[$i]->VirtualAddress);
		// 메모리 상에서 종료되는 위치
		$end_memory_address = sprintf('0x%08x', $start_memory_address + $section_array[$i]->VirtualSize);

		// 위치한 섹션을 찾았을 경우
		if ($import_table_memory_address >= $start_memory_address && $import_table_memory_address <= $end_memory_address)
		{
			// Import_Address_Table 개수 구하기
			// 전체 IMPORT ADDRESS TABLE 의 사이즈에서 구조체 하나의 크기인 20byte를 나눈다
			$import_table_sections = $import_table_size / 20 - 1;

			// 관련 정보 출력
			echo 'Section Name : '.$section_array[$i]->Name.'<br />';
			echo 'Section File Start Address : '.$start_file_address.'<br />';
			echo 'Section File End Address : '.$end_file_address.'<br />';
			echo 'Section Memory Start Address : '.$start_memory_address.'<br />';
			echo 'Section Memory End Address : '.$end_memory_address.'<br />';
			echo 'Import Address Table Rows : '.$import_table_sections.'<br /><br />';

			for ($j = 0; $j < $import_table_sections; $j++)
			{
				// RVA to RAW 수행
				$raw_file_offset = $import_table_address - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
				$raw_file_offset = sprintf("0x%08x", $raw_file_offset + ($j * 20));
				// 관련 정보 출력 시작
				echo 'RVA to RAW : '.$import_table_address.' => '.$raw_file_offset.'<br />';
				echo '<br />';

				// 파일의 포인터지점을 임시로 이동
				$temp_file_offset = $byte->file_offset;
				$byte->setPointer($raw_file_offset);
				// OriginalFirstThunk
				$original_first_thunk = $byte->getReadBytes(4);
				$original_first_thunk = $byte->getLittleEndian($original_first_thunk);
				echo 'IMAGE_THUNK_DATA 구조체의 RVA (OriginalFirstThunk) = "';
				echo $original_first_thunk;
				echo '"';

				echo '<br />';

				// TimeDateStamp
				$time_date_stamp = $byte->getReadBytes(4);
				$time_date_stamp = $byte->getLittleEndian($time_date_stamp);
				echo 'TimeDateStamp = "';
				echo $time_date_stamp;
				echo '" ; ';
				echo gmdate('Y.m.d H:i:s', hexdec($time_date_stamp));

				echo '<br />';

				// ForwarderChain
				$forwarder_chain = $byte->getReadBytes(4);
				$forwarder_chain = $byte->getLittleEndian($forwarder_chain);
				echo 'ForwarderChain = "';
				echo $forwarder_chain;
				echo '"';

				echo '<br />';

				// Name
				$name = $byte->getReadBytes(4);
				$name = $byte->getLittleEndian($name);
				echo 'Name = "';
				echo $name;
				echo '"';

				echo '<br />';

				// FirstThunk
				$first_thunk = $byte->getReadBytes(4);
				$first_thunk = $byte->getLittleEndian($first_thunk);
				echo 'FirstThunk = "';
				echo $first_thunk;
				echo '"';

				echo '<br />';

				// 함수 모듈명 구하기
				// RVA to RAW
				$module_name_raw_offset = $name - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
				// 사용된 모듈 이름 구하기
				$word = 0xff;
				$iat_import_module_name = '';
				// NULL 문자를 발견 할 때 까지 함수이름 설정
				while ($word != "\0")
				{
					$word = $byte->binToAscii($byte->getBytes($module_name_raw_offset++, 1));
					// 함수 이름 셋팅
					$iat_import_module_name .= $word;
				}
				// 구한 모듈의 이름을 출력
				echo '<br />';
				echo 'Import ModuleName : ASCII "<b>'.$iat_import_module_name.'</b>"';
				echo '<br /><br />';

				// OriginalFirstThunk (INT) 구하기
				// RVA to RAW
				$original_first_thunk_raw_offset = $original_first_thunk - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
				$original_first_thunk_raw_offset = sprintf('0x%08x', $original_first_thunk_raw_offset);
				//echo $original_first_thunk_raw_offset;

				// IMAGE_THUNK_DATA 구하기
				/*
				typedef struct _IMAGE_THUNK_DATA32 {
					union {
						pbyte forwarderString;
						pdword function;
						dword ordinal;
						pimage_import_by_name addressOfData;
					} u1;
				} IMAGE_THUNK_DATA32;
				*/

				// FirstThunk (IAT) 구하기
				$iat_func_address = array();
				$first_thunk_raw_offset = $first_thunk - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
				$first_thunk_raw_offset = sprintf('0x%08x', $first_thunk_raw_offset);
				$byte->setPointer($first_thunk_raw_offset);
				for ($k = 0; true; $k++)
				{
					$iat_func_address[$k] = $byte->getReadBytes(PE_ADDR_SIZE);
					$iat_func_address[$k] = $byte->getLittleEndian($iat_func_address[$k]);

					// 루프 탈출
					if ($iat_func_address[$k] == 0x00000000) break;
				}

				//$end_of_import_length = strlen($iat_import_module_name);
				for ($k = 0; ; $k++)
				{
					$int_address = $byte->getBytes($original_first_thunk_raw_offset + ($k * PE_ADDR_SIZE), PE_ADDR_SIZE);
					$int_address = $byte->getLittleEndian($int_address);
					// RVA to RAW
					// IMAGE_IMPORT_BY_NAME 구하기
					$int_address_raw_offset = $int_address - $section_array[$i]->VirtualAddress + $section_array[$i]->PointerToRawData;
					$int_address_raw_offset = sprintf('0x%0'.(PE_ADDR_SIZE*2).'x', $int_address_raw_offset);

					// 함수의 끝부분 인지를 검사
					//$end_of_import = $byte->binToAscii($byte->getBytes($byte->file_offset, $end_of_import_length));
					//if (str_replace($iat_import_module_name, '', $end_of_import) != $end_of_import)
					if ($iat_func_address[$k] == 0x00000000)
					{
						// 읽어온 다음 데이터가 모듈 이름하고 일치할 경우 Import 부분의 종료
						echo 'End Of Import : <b>'.$iat_import_module_name.'</b>';
						echo '<br />';
						break;
					}
					else
					{
						// Hint
						$hint = $byte->getBytes(hexdec($int_address_raw_offset), 2);
						$hint = $byte->getLittleEndian($hint);
						//$hint = hexdec($hint);

						// 사용된 모듈의함수 이름 구하기
						$word = 0xff;
						$iat_import_function_name = '';
						// NULL 문자를 발견 할 때 까지 함수이름 설정
						$temp_int_raw_offset = $int_address_raw_offset;
						$temp_int_raw_offset = hexdec($temp_int_raw_offset) + ($k * PE_ADDR_SIZE) + 2;
						while ($word != "\0")
						{
							$word = $byte->binToAscii($byte->getBytes(2 + $int_address_raw_offset++, 1));
							// 이름값이 없을경우 루프 탈출
							if ($word == "\0") break;
							// 함수 이름 셋팅
							$iat_import_function_name .= $word;
						}

						$iat_func_address_number = $byte->getBytes($first_thunk_raw_offset + ($k * PE_ADDR_SIZE), PE_ADDR_SIZE);
						$iat_func_address_number = $byte->getLittleEndian($iat_func_address_number);
						$firstBit = hexdec(substr($iat_func_address_number, 2, 1));
						if ($firstBit < 8 && $iat_func_address_number > 0x00 && $iat_import_function_name != '')
						//if ($iat_import_function_name != '')
						{
							// Hint
							echo 'Hint = "';
							echo $hint;
							echo '"';

							echo '<br />';

							// 멩글링된 함수의 이름을 정상적인 함수의 이름으로 바꾸어 출력한다.
							$undname = $iat_import_function_name;
							$byteStr = new ByteString($undname);
							// 멩글링 여부를 확인
							if ($byteStr->getBytes(0, 1) == '?')
							{
								if (strpos($undname, 'ERROR') != -1)
								{
									$undname = '<span style="color:#f00;">'.$undname.'</span>';
								}
								echo 'UNDNAME : <b>'.$undname.'</b>';
								echo '<br />';
							}
							else
							{
								// 맹글링 되어있지 않은 경우 진하게 설정
								$iat_import_function_name = '<b>'.$iat_import_function_name.'</b>';
							}
							// FunctionName
							echo 'FunctionName = "';
							echo $iat_import_function_name;
							echo '"';

							echo '<br />';

							// FunctionAddress
							echo 'FunctionAddress = "<b>';
							echo $iat_func_address_number;
							echo '</b>"';

							echo '<br /><br />';
						}
						else
						{
							// 아직 IAT 부분이 끝나지 않았는데 함수명이 나오지 않은 경우
							// 맨앞의 4바이트가 0x8000 으로 시작하는경우
							// Ordinal으로 함수 명을 구성하는것으로 간주한다.
							// 최상위 비트가 1인경우 Ordinal 로 간주한다.
							$tm_int_address = $int_address;
							$int_address = hexdec($int_address);
							if ((PE_ADDR_SIZE == 4 && ($int_address & 0x80000000)) || (PE_ADDR_SIZE == 8 && ($int_address & 0x8000000000000000)))
							{
								if (PE_ADDR_SIZE == 4)
								{
									// 뒤에서 2byte만 가져온다
									$dword = sprintf('0x%0'.PE_ADDR_SIZE.'x', $int_address & 0x0000ffff);
								}
								else
								if (PE_ADDR_SIZE == 8)
								{
									// 뒤에서 4byte만 가져온다
									$dword = '0x'.(substr($tm_int_address, 10, 8));
								}
								// Ordinal
								echo 'Ordinal = "<b>';
								echo $dword;
								echo '</b>"';

								echo '<br /><br />';
							}
						}
					}
				}

				// 파일의 포인터 지점을 다시 원상태로 되돌리기
				$byte->setPointer($temp_file_offset);
				echo '<br />';
			}
		}
	}

	$byte->_Byte();
}
?>
</body>
</html>
