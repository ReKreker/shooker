from lief import parse
from subprocess import run

from internal.other import *


class Compile:
    """Translate "patch" from xml to asm"""

    def __init__(self, cc: str, path: Path) -> None:
        self.cc = cc
        self.code = ""
        self.path = path
        self.inc_libs = []
        self.inc_fncs = []
        self.whitelist_funcs = []

    def include_lib(self, inc: str) -> None:
        if not inc:
            raise NotFound("Include lib")

        self.inc_libs.append(inc)

    def include_func(self, name: str, proto: str, addr: int) -> None:
        if not name or not proto or not addr:
            raise NotFound("Name/proto/addr for include func")

        # use Labels as Values https://gcc.gnu.org/onlinedocs/gcc/Labels-as-Values.html
        decl = f"#define {name} {name}_jmp: (({proto.replace('FUNC', '(*)')})((long)&&{name}_jmp-{addr}))"
        self.inc_fncs.append(decl)

    def assemble_transl(self) -> None:
        """Some asm-tricks"""
        # stuff like #include
        self.code += "\n".join(self.inc_libs) + "\n"

        # asm-trick to avoid broken xref for string from another segment
        self.code += "#define _s(string) ((char *)(const char []){string})\n"

        # func declaration stuff
        self.code += "\n".join(self.inc_fncs) + "\n"

    def add_func_to_transl(self, fnc_name: str, fnc_proto: str, fnc_code: str) -> None:
        """Assemble hook-function"""
        if not fnc_name or not fnc_proto or not fnc_code:
            raise NotFound(f"Name/code/proto to add func's definition")

        self.code += "\n" + fnc_proto.replace("FUNC", fnc_name) + "{" + fnc_code + "}"

        # to avoid extract smth like __do_global_dtors_aux or frame_dummy
        self.whitelist_funcs.append(fnc_name)

    def compile_transl(self, txt_addr: int) -> FuncsInfo:
        """Compile patch(s)"""

        (self.path / "translation.c").write_text(self.code)

        # uncomment to look translation.c
        # __import__("IPython").embed()

        cmd = [
            self.cc,
            "-fPIC",
            "--no-builtin",
            "-c",
            "-o",
            self.path / "translation.o",
            self.path / "translation.c",
        ]

        if run(cmd).returncode:
            raise CompileFail(cmd)

        cmd = [
            self.cc,
            "-shared",
            self.path / "translation.o",
            "-o",
            self.path / "libtranslation.so",
            f"-Wl,--section-start=.text={txt_addr}",
        ]
        if run(cmd).returncode:
            raise CompileFail(cmd)

        funcs_info = {}

        trs_bin = parse((self.path / "libtranslation.so").name)
        txt = trs_bin.get_section(".text")
        start = txt.virtual_address
        end = start + txt.size
        offset = 0

        # extract bytes of each function
        for sym in trs_bin.static_symbols:
            if (
                start <= sym.value
                and sym.value < end
                and sym.name in self.whitelist_funcs
            ):
                content = trs_bin.get_content_from_virtual_address(sym.value, sym.size)
                funcs_info[sym.name] = {"content": content, "offset": offset}
                offset += len(content)

        (self.path / "translation.c").unlink()
        (self.path / "translation.o").unlink()
        (self.path / "libtranslation.so").unlink()

        return funcs_info
