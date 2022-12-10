from lief import parse
from subprocess import run

from shooker.internal.other import *


class Compile:
    """Translate "patch" from xml to asm"""

    def __init__(self, root_xml: XmlElem, path: Path) -> None:
        self.path = path
        self.clear_include_info()

        xml = root_xml.find("default_cc")
        if xml is None:
            return
        self.deflt = self.parse_all_cc(xml)

    def parse_all_cc(self, xml: XmlElem) -> Dict[str, str]:
        """get compiler, arch & mode from xml element"""
        tmp = {}
        tmp["compiler"] = self.parse_cc(xml, "compiler")
        tmp["arch"] = self.parse_cc(xml, "arch")
        tmp["mode"] = self.parse_cc(xml, "mode")
        return tmp

    def parse_cc(self, xml: XmlElem, name: str) -> str | None:
        """get compiler info from xml element"""
        logging.debug(f"Extract {name} from a xml element")
        if xml.find(name) is not None:
            self.curr[name] = xml.find(name).text
        elif self.deflt[name] is not None:
            self.curr[name] = self.deflt[name]
        elif os.getevn("SHOOKER_" + name.upper()):
            self.curr[name] = os.getevn("SHOOKER_" + name.upper())
            logging.debug(f"Use env-variable")
        else:
            return None
        return self.curr[name]

    def clear_include_info(self) -> None:
        """Clear parsed info about functions from specific library"""
        self.code = ""
        self.inc_libs = []
        self.inc_fncs = []
        self.whitelist_funcs = []
        self.curr = {}
        self.deflt = {"compiler": None, "arch": None, "mode": None}

    def include_lib(self, inc: str) -> None:
        """Add library to hook's code"""
        logging.debug(f"Include lib {inc}")
        if not inc:
            raise NotFound("Include lib")

        self.inc_libs.append(inc)

    def include_func(self, name: str, proto: str, addr: int) -> None:
        """Add function definition to hook's code"""
        if not name or not proto or not addr:
            raise NotFound("Name/proto/addr for include func")

        proto = proto.replace('FUNC', '(*)')
        decl = (f"#define {name} GET_FUNC({proto}, {name}, {addr})")
        logging.debug(f"Include func {decl}")
        self.inc_fncs.append(decl)

    def assemble_transl(self) -> None:
        """Some asm-tricks"""
        # stuff like #include
        self.code += "\n".join(self.inc_libs)

        # asm-trick to avoid broken xref for string from another segment
        self.code += "\n#define _s(string) ((char *)(const char []){string})\n"

        # asm-trick for unique jump label for relative jump funcs
        # use Labels as Values            https://gcc.gnu.org/onlinedocs/gcc/Labels-as-Values.html
        # use Statements and Expressions  https://gcc.gnu.org/onlinedocs/gcc/Statement-Exprs.html
        # use __COUNTER__ to define a uniq jump label
        self.code += (
            "\n#define GET_FUNC_(proto, func_name, addr, cnt)" +
            " ((proto)({func_name##_jmp_##cnt:(long)&&func_name##_jmp_##cnt-addr;}))"
        )
        self.code += ("\n#define GET_FUNC(proto, func_name, addr)" +
                      " GET_FUNC_(proto, func_name, addr, __COUNTER__)\n")

        # func declaration stuff
        self.code += "\n".join(self.inc_fncs) + "\n"

    def add_func_to_transl(self, fnc_name: str, fnc_proto: str,
                           fnc_code: str) -> None:
        """Assemble hook-function"""
        if not fnc_name or not fnc_proto or not fnc_code:
            raise NotFound(f"Name/code/proto to add func's definition")

        self.code += "\n" + fnc_proto.replace("FUNC",
                                              fnc_name) + "{" + fnc_code + "}"

        # to avoid extract smth like __do_global_dtors_aux or frame_dummy
        self.whitelist_funcs.append(fnc_name)

    def compile_transl(self, txt_addr: int) -> FuncsInfo:
        """Compile patch(s)"""

        if self.curr.get("compiler") is None:
            raise NotFound("Compiler")

        self.code = fix_indent(self.code)
        (self.path / "translation.c").write_text(self.code)

        logging.debug("=" * 70 + "\n" + self.code + "\n" + "=" * 70)

        cmd = run([
            self.curr["compiler"], "-fPIC", "--no-builtin", "-c", "-o",
            self.path / "translation.o", self.path / "translation.c"
        ],
                  capture_output=True)
        if cmd.stderr != b"":
            raise CompileFail(cmd.stderr.decode("utf8"))

        cmd = run([
            self.curr["compiler"],
            "-shared",
            self.path / "translation.o",
            "-o",
            self.path / "libtranslation.so",
            f"-Wl,--section-start=.text={hex(txt_addr)}",
        ],
                  capture_output=True)
        if cmd.stderr != b"":
            raise CompileFail(cmd.stderr.decode("utf8"))

        funcs_info = {}

        trs_bin = parse((self.path / "libtranslation.so").name)
        txt = trs_bin.get_section(".text")
        start = txt.virtual_address
        end = start + txt.size
        offset = 0
        logging.debug(f"Translation offset {hex(start)}")

        # extract bytes of each function
        for sym in trs_bin.static_symbols:
            if (start <= sym.value and sym.value < end
                    and sym.name in self.whitelist_funcs):
                logging.debug(f"Created {sym.name} with size {sym.size}")
                content = trs_bin.get_content_from_virtual_address(
                    sym.value, sym.size)
                funcs_info[sym.name] = {"content": content, "offset": offset}
                offset += len(content)

        (self.path / "translation.c").unlink()
        (self.path / "translation.o").unlink()
        (self.path / "libtranslation.so").unlink()

        self.clear_include_info()

        return funcs_info
