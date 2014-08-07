<?php

// 용량에 관계없이 해당 파일의 일정 바이트를 제어
// 파일 바이트 단위 제어 함수
class Byte
{
	var $fp = null;
	var $filename = '';
	var $file_offset = 0;
	// 생성자
	function Byte($filename)
	{
		if ($filename != '')
		{
			$this->file_offset = 0;
			$this->filename = $filename;
			$this->fp = fopen($filename, 'r');
		}
	}

	// 현재 포인터 위치로 부터 파일의 포인터 위치를 원하는 곳으로 설정
	function setPointer($pointer)
	{
		$this->file_offset = hexdec($pointer);
	}

	// 파일에서 현재 설정된 포인터로부터 원하는 바이트 만큼을 얻어온다
	function getReadBytes($length)
	{
		fseek($this->fp, $this->file_offset);

		// 해당 바이트 만큼 구하기
		$byte = fread($this->fp, $length);
		//if ($byte == '') return '';

		$retn = '';
		for ($i = 0; $i < $length; $i++)
			$retn .= sprintf("%02x", @ord($byte[$i]));

		// 구한 바이트의 길이만큼 포인터 이동
		$this->file_offset += $length;

		return $retn;
	}

	// 파일에서 $pointer 로부터 원하는 바이트만큼을 얻어온다
	function getBytes($pointer, $length)
	{
		// 해당 바이트 만큼 구하기
		fseek($this->fp, $pointer);
		$byte = fread($this->fp, $length);

		$retn = '';
		for ($i = 0; $i < $length; $i++)
			$retn .= sprintf("%02x", @ord($byte[$i]));

		return $retn;
	}

	// Little-Endian 형식으로 지정된 데이터를 변환후 리턴
	function getLittleEndian(&$data)
	{
		$retn = '';
		$length = strlen($data);
		for ($i = 0; $i < $length; $i+=2)
		{
			$retn[($length-$i)/2-1] = substr($data, $i, 2);
		}
		// 재 정렬
		ksort($retn);

		return '0x'.implode('', $retn);
	}

	// Binary 형식의 문자열을 ASCII 형식의 문자열로 변경
	function binToAscii($binary_str)
	{
		$retn = '';
		$length = strlen($binary_str);
		for ($i = 0; $i < $length; $i+=2)
		{
			$retn .= chr(hexdec(substr($binary_str, $i, 2)));
		}
		return $retn;
	}

	// 파괴자
	function _Byte()
	{
		if ($this->filename != '')
		{
			fclose($this->fp);
		}
	}
}
?>