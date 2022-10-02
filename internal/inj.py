from internal.types import *

from lief.ELF import Section

class Inject:
    """Create shook section and some hooking stuff"""

    def __init__(self, target: liefBin, asm) -> None:
        self.bin = target
        self.asm = asm

    def shook_sect_init(self) -> None:
        """Create section to find out base address for linker"""
        section = Section(".shook", lief.ELF.SECTION_TYPES.PROGBITS)
        section += lief.ELF.SECTION_FLAGS.EXECINSTR
        section += lief.ELF.SECTION_FLAGS.WRITE
        section.content = [0]*0x2000  # 100500 iq
        self.bin.add(section, loaded=True)

    def shook_sect_fill(self, content: list) -> None:
        """Fill section with hooks by compiled payloads"""
        self.bin.get_section(".shook").content = content

    def hook(self, fnc_name: str, hook_offset: int, payl_offset: int) -> None:
        """Replace first instruction of function at jump to the payload in .shook section"""
        target_addr = self.bin.get_section(".shook").virtual_address + \
            payl_offset - \
            hook_offset
        jmp_inst = self.asm.jump(target_addr)

        value = [i for i in jmp_inst]
        addr = self.bin.get_static_symbol(fnc_name).value
        self.bin.patch_address(addr, value)
