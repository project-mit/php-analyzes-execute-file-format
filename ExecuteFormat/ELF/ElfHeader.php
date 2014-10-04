<?php
namespace AnalyzesExecuteFileFormat\ExecuteFormat\ELF;

class ElfHeader
{
    const EI_NIDENT = 16;

    public $e_ident = [
        'el_mag0' => 0x00,
        'el_mag3' => '',
        'el_class' => 0x00,
        'el_data' => 0x00,
        'el_version' => 0x00,
        'el_osabi' => 0x00,
        'el_abiversion' => 0x00,
        'el_pad' => [0, 0, 0, 0, 0, 0, 0]
    ];
    public $e_type;
    public $e_machine;
    public $e_version;
    public $e_entry;
    public $e_phoff;
    public $e_shoff;
    public $e_flags;
    public $e_ehsize;
    public $e_phentsize;
    public $e_phnum;
    public $e_shentsize;
    public $e_shnum;
    public $e_shstrndx;
}
?>