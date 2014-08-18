<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\PE;

class ImageDosHeader
{
    public $magic;
    public $cblp;
    public $cp;
    public $crlc;
    public $cparhdr;
    public $minalloc;
    public $maxalloc;
    public $ss;
    public $sp;
    public $csum;
    public $ip;
    public $cs;
    public $lfarlc;
    public $ovno;
    public $reservd1 = [0, 0, 0, 0];
    public $oemid;
    public $oeminfo;
    public $reservd2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    public $lfanew;
}
?>
