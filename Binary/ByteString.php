<?php
// 바이트 단위의 문자열을 관리
class ByteString
{
	var $data = '';
	function ByteString($str)
	{
		$this->data = $str;
	}

	// 설정된 문자열로 부터 해당 위치의 해당 개수를 리턴
	function getBytes($offset, $length)
	{
		return substr($this->data, $offset, $length);
	}
}
?>
