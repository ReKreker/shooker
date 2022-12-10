import lief
import xml
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
    "XmlElem",
    "Dict",
    "List",
]

LiefBin = NewType("liefBin",
                  lief.ELF.Binary | lief.MachO.Binary | lief.PE.Binary)
LiefSect = NewType("liefSec",
                   lief.ELF.Section | lief.MachO.Section | lief.PE.Section)
FuncsInfo = NewType("funcsInfo", List[Dict[list, int]])
XmlElem = NewType("xmlElem", xml.etree.ElementTree.Element)


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
    intend_level = 0

    lines = code.split("\n")
    for i in range(len(lines)):
        line = lines[i].strip()
        for char in line:
            if char != "\r":
                res += char

            if char == "{":
                intend_level += 1
            elif len(lines) - 1 != i and lines[i + 1].strip() == "}":
                intend_level = 0
            elif char == "}":
                if intend_level > 0:
                    intend_level -= 1
        res += "\n" + " " * 4 * intend_level
    return res
