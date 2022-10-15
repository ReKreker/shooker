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
