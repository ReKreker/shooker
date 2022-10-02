import lief

from typing import NewType, Dict, List

liefBin = NewType("liefBin", lief.ELF.Binary | lief.MachO.Binary | lief.PE.Binary)
liefSect = NewType("liefSec", lief.ELF.Section | lief.MachO.Section | lief.PE.Section)
funcsInfo = NewType("funcsInfo", List[Dict[list, int]])