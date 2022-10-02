from internal.types import *

from subprocess import run


class Compile:
    """Translate "patch" from xml to asm"""

    def __init__(self, cc: str, path: str) -> None:
        self.cc = cc
        self.code = ""
        self.path = path
        self.inc_libs = []
        self.inc_fncs = []
        self.whitelist_funcs = []

    def include_lib(self, inc: str) -> None:
        t = type(inc)
        if t == None:
            raise Exception("Include lib is None")

        self.inc_libs.append(inc)

    def include_func(self, name: str, proto: str, addr: int) -> None:
        if name == None or name == "" or \
           proto == None or proto == "" or \
           addr == None:
            raise Exception("Name/proto/addr is None")

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
        if fnc_name == "" or fnc_name == None \
                or fnc_proto == "" or fnc_proto == None \
                or fnc_code == "":
            raise Exception(f"Cannot add func with no (name|code|proto)")

        self.code += "\n" +\
                     fnc_proto.replace("FUNC", fnc_name) +\
                     "{" +\
                     fnc_code +\
                     "}"

        # to avoid extract smth like __do_global_dtors_aux or frame_dummy
        self.whitelist_funcs.append(fnc_name)

    def compile_transl(self, txt_addr: int) -> funcsInfo:
        """Compile patch(s)"""
        if self.code == "":
            raise Exception("Code is None")

        (self.path / "translation.c").write_text(self.code)

        # uncomment to look translation.c
        # __import__("IPython").embed()

        cmd = [self.cc, "-fPIC", "--no-builtin", "-c", "-o",
               self.path/"translation.o", self.path/"translation.c"]

        out = run(cmd)
        if out.returncode:
            print(cmd)
            raise Exception(out)

        cmd = [self.cc, "-shared", self.path/"translation.o", "-o",
               self.path/"libtranslation.so", f"-Wl,--section-start=.text={txt_addr}"]
        out = run(cmd)
        if out.returncode:
            print(cmd)
            raise Exception(out)

        funcs_info = {}

        trs_bin = lief.parse((self.path/"libtranslation.so").name)
        txt = trs_bin.get_section(".text")
        start = txt.virtual_address
        end = start + txt.size
        offset = 0

        # extract bytes of each function
        for sym in trs_bin.static_symbols:
            if start <= sym.value and sym.value < end and sym.name in self.whitelist_funcs:
                content = trs_bin.get_content_from_virtual_address(
                    sym.value, sym.size)
                funcs_info[sym.name] = {"content": content, "offset": offset}
                offset += len(content)

        (self.path/"translation.c").unlink()
        (self.path/"translation.o").unlink()
        (self.path/"libtranslation.so").unlink()

        return funcs_info
