import capstone

from internal.other import *

from lief.ELF import ARCH


class Assembler:
    """Arch-depended stuff"""

    def __init__(self, target: LiefBin, arch: str, mode: str) -> None:
        self.bin = target
        self.arch = self.bin.header.machine_type
        cs_arch, cs_mode = getattr(capstone, arch), getattr(capstone, mode)
        self.md = capstone.Cs(cs_arch, cs_mode)

    def jump(self, target_addr: int) -> bytes:
        """Create jmp-instruction to target_addr"""
        if self.arch == ARCH.x86_64:
            target_addr -= 5  # length of jmp instr
            return b"\xE9" + target_addr.to_bytes(4, "little")
        else:
            raise Unimplemented(f"Assemble jump for {arch}")

    def brute_ptl(self, section: LiefSect, target_addr: int) -> int:
        """Find plt-stub for specific function from .got.plt"""
        cont = section.content.tobytes()
        plt_offs = section.virtual_address

        if self.arch == ARCH.x86_64:
            for instr in self.md.disasm(cont, plt_offs):
                if instr.mnemonic != "jmp" or "word ptr [rip" not in instr.op_str:
                    continue

                instr_offs = int.from_bytes(instr.bytes[2:], "little")

                # offset from instruction + current entry plt position + len of jmp instruction
                if instr_offs + instr.address + instr.size == target_addr:
                    return instr.address
        else:
            raise Unimplemented(f"Enumerating plt for {self.arch}")

        raise NotFound("Include function not found")

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

                if (
                    instr.mnemonic == "sub"
                    and register is not None
                    and instr.op_str.startswith(register)
                ):
                    sub_instr = instr

                if (
                    instr.mnemonic == "call"
                    and sub_instr is not None
                    and 2 <= instr.size <= 3
                ):
                    call_ip = instr.address
                    break

            if lea_ip == 0:
                raise NotFound(f"Get IP instruction")
            elif sub_instr is None:
                raise NotFound(f"Sub {register}, #const")
            elif call_ip == 0:
                raise NotFound(f"Register-jump instruction")

            sub_value = int.from_bytes(sub_instr.bytes[2:], "little")
            relative_offs = func_offs + lea_ip - sub_value
            sub_bytes = sub_instr.bytes[:2] + relative_offs.to_bytes(4, "little")

            cont[sub_instr.address : sub_instr.address + sub_instr.size] = sub_bytes

        else:
            raise Unimplemented(f"Patch sub-instruction for {arch}")

        return [i for i in cont]
