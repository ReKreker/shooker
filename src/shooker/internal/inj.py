from lief.ELF import Section, SECTION_FLAGS, SECTION_TYPES, Segment, SEGMENT_FLAGS, SEGMENT_TYPES

from shooker.internal.other import *

MAX_PATCH_SIZE = 1024
INJ_TYPE = 1 # 0 - for segment, 1 - for section

class Inject:
    """Create shook section and some hooking stuff"""

    def __init__(self, target: LiefBin, asm) -> None:
        self.bin = target
        self.asm = asm
        self.last_load_segm = None
        self.shook_init()

    def shook_init(self) -> None:
        if INJ_TYPE == 0:
            self.segm_init()
        elif INJ_TYPE == 1:
            self.sect_init()
        else:
            raise NotFound("Injection type for shook init")

    def sect_init(self) -> None:
        """Create section to find out injection base address"""
        if self.bin.get_section(".shook") is not None:
            logging.debug("Section .shook exists")
            return

        logging.debug("Create .shook section")
        section = Section(".shook", SECTION_TYPES.PROGBITS)
        section += SECTION_FLAGS.EXECINSTR
        section += SECTION_FLAGS.WRITE
        section.content = [0] * MAX_PATCH_SIZE
        self.bin.add(section, loaded=True)

    def segm_init(self) -> None:
        """Create section to find out injection base address"""
        logging.debug("Create .shook segment")
        segment = Segment()
        segment.content = [0] * MAX_PATCH_SIZE
        segment.alignment = 512
        segment.type = SEGMENT_TYPES.LOAD
        segment.add(SEGMENT_FLAGS.R)
        segment.add(SEGMENT_FLAGS.X)
        self.bin.add(segment)

    def shook_fill(self, content: list) -> None:
        if len(content) > MAX_PATCH_SIZE:
            raise Unimplemented("Too big size for patch")

        if INJ_TYPE == 0:
            self.segm_fill(content)
        elif INJ_TYPE == 1:
            self.sect_fill(content)
        else:
            raise NotFound("Injection type for shook fill")

    def sect_fill(self, content: list) -> None:
        """Fill section with hooks by compiled payloads"""
        self.bin.get_section(".shook").content = content

    def segm_fill(self, content: list) -> None:
        """Fill segment with hooks by compiled payloads"""
        addr = self.get_inj_segm_addr()
        self.bin.patch_address(addr, content)

    def get_inj_addr(self) -> int:
        if INJ_TYPE == 0:
            return self.get_inj_segm_addr()
        elif INJ_TYPE == 1:
            return self.get_inj_sect_addr()
        else:
            raise NotFound("Injection type for shook inj addr")

    def get_inj_sect_addr(self) -> int:
        return self.bin.get_section(".shook").virtual_address

    def get_inj_segm_addr(self) -> int:
        if self.last_load_segm is not None:
            return self.last_load_segm.virtual_address

        for segm in self.bin.segments:
            if segm.type == SEGMENT_TYPES.LOAD:
                self.last_load_segm = segm
        
        if self.last_load_segm is None:
            raise NotFound("Injected segment")

        return self.last_load_segm.virtual_address


    def hook(self, fnc_name: str, hook_offset: int, payl_offset: int) -> None:
        """Replace first instruction of function at jump to the payload in .shook section"""
        target_addr = (
            self.get_inj_addr() + payl_offset - hook_offset
        )
        jmp_inst = self.asm.jump(target_addr)

        value = [i for i in jmp_inst]
        addr = self.bin.get_static_symbol(fnc_name).value
        self.bin.patch_address(addr, value)
