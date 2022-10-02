from internal.types import *
from internal.asm import Assembler

class FuncTable:
    """To resolve funcs"""

    def __init__(self, target: liefBin, asm) -> None:
        self.bin = target
        self.asm = asm
        self.fncs = []

    def load_symbol(self, fnc_name: str) -> int:
        """Get definition of symbol from .text section in hooked lib"""
        fnc = self.bin.get_static_symbol(fnc_name)
        if type(fnc) != lief.ELF.Symbol:
            raise Exception(f"Static function {fnc_name} exception")

        self.fncs.append({"name": fnc.name, "addr": fnc.value})
        return fnc.value

    def load_import(self, fnc_name: str) -> int:
        """Get definition of import symbol from .plt section in hooked lib"""
        fnc = self.bin.get_relocation(fnc_name)
        if type(fnc) != lief.ELF.Relocation:
            raise Exception(f"Dynamic function {fnc_name} exception")

        plt = self.bin.get_section(".plt")
        addr = self.asm.brute_ptl(plt, fnc.address)
        self.fncs.append({"name": fnc.symbol.name, "addr": addr})
        return addr
