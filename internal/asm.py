import capstone

from internal.types import *

from lief.ELF import ARCH
from re import search


class Assembler:
    """Arch-depended stuff"""

    def __init__(self, target: liefBin, arch: str, mode: str) -> None:
        self.bin = target
        self.arch = self.bin.header.machine_type
        cs_arch, cs_mode = getattr(capstone, arch), getattr(capstone, mode)
        self.md = capstone.Cs(cs_arch, cs_mode)

    def jump(self, target_addr: int) -> bytes:
        """Create jmp-instruction to target_addr"""
        if self.arch == ARCH.x86_64:
            target_addr -= 5  # length of jmp instr
            jmp_inst = b"\xE9" + target_addr.to_bytes(4, "little")
        else:
            raise Exception(f"Assemble jump isn't implemented for {arch}")

        return jmp_inst

    def brute_ptl(self, section: liefSect, target_addr: int) -> int:
        """Find plt-stub for specific function from .got.plt"""
        cont = section.content.tobytes()
        plt_offs = section.virtual_address
        found = False

        if self.arch == ARCH.x86_64:
            for instr in self.md.disasm(cont, plt_offs):
                if instr.mnemonic != "jmp" or search(r"word ptr \[rip", instr.op_str) == None:
                    continue

                instr_offs = int.from_bytes(instr.bytes[2:], "little")

                # offset from instruction + current entry plt position + len of jmp instruction
                if instr_offs + instr.address + 6 == target_addr:
                    found = True
                    break
        else:
            raise Exception(f"Bruteforcing plt isn't implemented for {arch}")

        if not found:
            raise Exception("Include function not found")

        return instr.address

    def patch_sub_values(self, func_cont: list, func_offs: int) -> list:
        """Patch values that substracted from rip for relative-call instruction"""

        cont = bytearray(b"".join([i.to_bytes(1, "big") for i in func_cont]))
        register = None
        lea_ip = None
        sub_instr = None
        call_ip = 0

        if self.arch == ARCH.x86_64:
            for instr in self.md.disasm(cont, 0):
                # print(instr)
                if instr.mnemonic == "lea" and "[rip - 7]" in instr.op_str:
                    lea_ip = instr.address
                    register = instr.op_str.replace(", [rip - 7]", "")

                if instr.mnemonic == "sub" and register != None and instr.op_str.startswith(register):
                    sub_instr = instr

                if instr.mnemonic == "call" and sub_instr != None and 2 <= instr.size <= 3:
                    call_ip = instr.address
                    break

            if call_ip == 0:
                raise Exception("Cannot patch sub-instr")

            sub_value = int.from_bytes(sub_instr.bytes[2:], "little")
            relative_offs = func_offs + lea_ip - sub_value
            sub_bytes = sub_instr.bytes[:2] + \
                relative_offs.to_bytes(4, "little")

            cont[sub_instr.address:sub_instr.address+sub_instr.size] = sub_bytes

        else:
            raise Exception(
                f"Patch sub-instruction isn't implemented for {arch}")

        return [i for i in cont]
