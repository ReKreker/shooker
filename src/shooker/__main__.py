#!/usr/bin/python3
import lief
import xml.etree.ElementTree as ET

from argparse import ArgumentParser

from shooker.internal.asm import Assembler
from shooker.internal.ftb import FuncTable
from shooker.internal.inj import Inject
from shooker.internal.cmpl import Compile
from shooker.internal.other import *


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "--xml",
        type=Path,
        dest="config",
        default="hooks.xml",
        help="Hook config file (default: target_dir/hooks.xml)",
    )
    parser.add_argument("target_dir",
                        type=Path,
                        help="Directory with libs to hook")
    parser.add_argument("output_dir",
                        type=Path,
                        help="Directory to save hooked libs")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.target_dir.exists():
        raise NotFound("Target dir")

    if args.config.name == "hooks.xml":
        args.config = args.target_dir / "hooks.xml"
    if not args.config.exists():
        raise NotFound(f"Hook config from {args.config.name}")

    with open(args.config) as xml_file:
        parser = ET.parse(xml_file)

    shook = parser.getroot()
    cmpl = Compile(shook, args.target_dir)

    for lib in shook.iterfind("lib_hook"):
        lib_path = args.target_dir / lib.attrib["path"]
        logging.info(f"Patching {lib_path}...")

        target = lief.parse(str(lib_path.resolve()))

        _, arch, mode = cmpl.parse_all_cc(lib).values()
        if arch is None or mode is None:
            raise NotFound("Arch or mode for hooked liblary")
        asm = Assembler(target, arch, mode)
        ftb = FuncTable(target, asm)
        inj = Inject(target, asm)

        inc = lib.find("include")
        if inc is not None:
            # parse included libs
            for inc_lib in inc.iterfind("lib"):
                kind = inc_lib.attrib.get("kind")
                if kind == "system":
                    inc_value = f"#include <{inc}>"
                elif kind == "local":
                    inc_value = f'#include "{inc}"'
                else:
                    raise Wrong("Kind of include lib")
                cmpl.include_lib(inc_value)

            # parse included funcs
            for inc_fnc in inc.iterfind("func"):
                kind = inc_fnc.attrib.get("kind")
                name = inc_fnc.text
                if kind == "import":
                    addr = ftb.load_import(name)
                elif kind == "local":
                    addr = ftb.load_symbol(name)
                else:
                    raise Wrong("Kind of include func")
                proto = inc_fnc.attrib.get("proto")
                cmpl.include_func(name, proto, addr)

        # define included libs&funcs
        cmpl.assemble_transl()

        # compile hooks
        for to_hook in lib.iterfind("hook"):
            fnc_name = to_hook.attrib.get("name")
            fnc_proto = to_hook.attrib.get("proto")
            fnc_code = to_hook.text

            logging.info(f"Compiling hook for {fnc_name}")
            cmpl.add_func_to_transl(fnc_name, fnc_proto, fnc_code)
        inj_addr = inj.get_inj_addr()
        funcs_info = cmpl.compile_transl(inj_addr)

        logging.info("Patching the hook(s)...")
        content = []
        for func in funcs_info.values():
            arr = func["content"]
            offset = func["offset"] + inj_addr
            content += asm.patch_sub_values(arr, offset)
        inj.shook_fill(content)

        for to_hook in lib.iterfind("hook"):
            fnc_name = to_hook.attrib["name"]
            logging.info(f"Hooking {fnc_name}")

            fnc_offset = target.get_static_symbol(
                fnc_name).value  # address of func
            # offset of funcs
            payl_offset = funcs_info[fnc_name]["offset"]
            inj.hook(fnc_name, fnc_offset, payl_offset)

        outlib_path = str(args.output_dir / lib.attrib["path"])
        target.write(outlib_path)
    logging.info("Lib(s) patched")


if __name__ == "__main__":
    main()
