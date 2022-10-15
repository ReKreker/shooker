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
        logging.debug(f"Include lib {inc}")
        if not inc:
            raise NotFound("Include lib")

        self.inc_libs.append(inc)

    def include_func(self, name: str, proto: str, addr: int) -> None:
        if not name or not proto or not addr:
            raise NotFound("Name/proto/addr for include func")

        # use Labels as Values            https://gcc.gnu.org/onlinedocs/gcc/Labels-as-Values.html
        # and Statements and Expressions  https://gcc.gnu.org/onlinedocs/gcc/Statement-Exprs.html
        label = f"UNIQ_LINE({name}_jmp)"
        decl = (
            f"#define {name} (({proto.replace('FUNC', '(*)')})"
            + "({"
            + f"{label}:(long)&&{label}-{addr};"
            + "}))"
        )
        logging.debug(f"Include func {decl}")
        self.inc_fncs.append(decl)

    def assemble_transl(self) -> None:
        """Some asm-tricks"""
        # stuff like #include
        self.code += "\n".join(self.inc_libs)

        # asm-trick to avoid broken xref for string from another segment
        self.code += "\n#define _s(string) ((char *)(const char []){string})\n"

        # asm-trick for unique jump label for relative jump funcs
        self.code += "\n#define CONCAT_(prefix, suffix) prefix##suffix"
        self.code += "\n#define CONCAT(prefix, suffix) CONCAT_(prefix, suffix)"
        self.code += "\n#define UNIQ_LINE(prefix) CONCAT(prefix##_, __LINE__)\n"

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

        logging.debug("="*70 + "\n"+ self.code + "\n" + "="*70)

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
        logging.debug(f"Translation offset {hex(start)}")

        # extract bytes of each function
        for sym in trs_bin.static_symbols:
            if (
                start <= sym.value
                and sym.value < end
                and sym.name in self.whitelist_funcs
            ):
                logging.debug(f"Created {sym.name} with size {sym.size}")
                content = trs_bin.get_content_from_virtual_address(sym.value, sym.size)
                funcs_info[sym.name] = {"content": content, "offset": offset}
                offset += len(content)

        (self.path / "translation.c").unlink()
        (self.path / "translation.o").unlink()
        (self.path / "libtranslation.so").unlink()

        return funcs_info
