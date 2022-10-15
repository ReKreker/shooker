from lief import ELF
from dataclasses import dataclass

from shooker.internal.other import *


class FuncTable:
    """To resolve funcs"""

    def __init__(self, target: LiefBin, asm) -> None:
        self.bin = target
        self.asm = asm
        self.fncs = []

    def load_symbol(self, fnc_name: str) -> int:
        """Get definition of symbol from .text section in hooked lib"""
        fnc = self.bin.get_static_symbol(fnc_name)
        if not isinstance(fnc, ELF.Symbol):
            raise NotFound(f"Static function {fnc_name}")

        entry = FuncEntry(fnc.name, fnc.value)
        self.fncs.append(entry)
        logging.debug(f"Static {entry.name} loaded at {hex(entry.addr)}")
        return fnc.value

    def load_import(self, fnc_name: str) -> int:
        """Get definition of import symbol from .plt section in hooked lib"""
        fnc = self.bin.get_relocation(fnc_name)
        if not isinstance(fnc, ELF.Relocation):
            raise NotFound(f"Dynamic function {fnc_name}")

        plt = self.bin.get_section(".plt")
        jump_addr = self.asm.brute_ptl(plt, fnc.address)
        entry = FuncEntry(fnc.symbol.name, jump_addr)
        self.fncs.append(entry)
        logging.debug(f"Import {entry.name} loaded at {hex(entry.addr)}")
        return jump_addr


@dataclass
class FuncEntry:
    name: str
    addr: int
