import lief
import logging

from pathlib import Path
from typing import NewType, Dict, List

__all__ = [
    "Path",
    "LiefBin",
    "LiefSect",
    "FuncsInfo",
    "Unimplemented",
    "NotFound",
    "CompileFail",
    "Wrong",
    "logging",
    "fix_indent",
]

LiefBin = NewType("liefBin", lief.ELF.Binary | lief.MachO.Binary | lief.PE.Binary)
LiefSect = NewType("liefSec", lief.ELF.Section | lief.MachO.Section | lief.PE.Section)
FuncsInfo = NewType("funcsInfo", List[Dict[list, int]])


class Unimplemented(Exception):
    def __init__(self, msg):
        pass


class NotFound(Exception):
    def __init__(self, msg):
        pass


class CompileFail(Exception):
    def __init__(self, cmd):
        pass


class Wrong(Exception):
    def __init__(self, msg):
        pass


logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)


def fix_indent(code: str) -> str:
    res = ""
    intend_level, offs = 0, 0
    skip_space = False

    while offs < len(code):
        char = code[offs]
        offs += 1
        if char != "\r" and not (skip_space and char in [" ", "\t"]):
            res += char
            skip_space = False

        if char == "{":
            intend_level += 1
        elif char == "}":
            if intend_level > 0:
                intend_level -= 1
        elif char == "\n":
            skip_space = True
            res += "\t" * intend_level

    return res
