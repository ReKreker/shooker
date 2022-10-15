from lief.ELF import Section, SECTION_FLAGS, SECTION_TYPES

from shooker.internal.other import *


class Inject:
    """Create shook section and some hooking stuff"""

    def __init__(self, target: LiefBin, asm) -> None:
        self.bin = target
        self.asm = asm
        self.shook_sect_init()

    def shook_sect_init(self) -> None:
        """Create section to find out base address for linker"""
        if self.bin.get_section(".shook") is not None:
            logging.debug("Section .shook exists")
            return

        logging.debug("Create .shook section")
        section = Section(".shook", SECTION_TYPES.PROGBITS)
        section += SECTION_FLAGS.EXECINSTR
        section += SECTION_FLAGS.WRITE
        section.content = [0]*0x500
        self.bin.add(section, loaded=True)

    def shook_sect_fill(self, content: list) -> None:
        """Fill section with hooks by compiled payloads"""
        self.bin.get_section(".shook").content = content

    def hook(self, fnc_name: str, hook_offset: int, payl_offset: int) -> None:
        """Replace first instruction of function at jump to the payload in .shook section"""
        target_addr = (
            self.bin.get_section(".shook").virtual_address + payl_offset - hook_offset
        )
        jmp_inst = self.asm.jump(target_addr)

        value = [i for i in jmp_inst]
        addr = self.bin.get_static_symbol(fnc_name).value
        self.bin.patch_address(addr, value)
