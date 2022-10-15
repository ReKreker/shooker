#!/usr/bin/python3
import lief
import xml.etree.ElementTree as ET

from argparse import ArgumentParser

from internal.asm import Assembler
from internal.ftb import FuncTable
from internal.inj import Inject
from internal.cmpl import Compile
from internal.other import *


def main():
    parser = ArgumentParser()
    parser.add_argument(
        "--xml",
        type=Path,
        dest="config",
        default="hooks.xml",
        help="Hook config file (default: target_dir/hooks.xml)",
    )
    parser.add_argument("target_dir", type=Path, help="Directory with libs to hook")
    parser.add_argument("output_dir", type=Path, help="Directory to save hooked libs")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.target_dir.exists():
        raise NotFound("Target dir")

    if args.config.name == "hooks.xml":
        args.config = args.target_dir / "hooks.xml"
    if not args.config.exists():
        raise NotFound("Hook config")

    with open(args.config) as xml_file:
        parser = ET.parse(xml_file)

    shook = parser.getroot()
    cc = shook.find("compiler").text

    for lib in shook.iterfind("lib_hook"):
        lib_path = (args.target_dir / lib.attrib["path"]).name
        logging.info(f"Patching {lib_path}...")

        target = lief.parse(lib_path)

        cs_arch = lib.find("arch")
        cs_mode = lib.find("mode")
        if cs_arch is None or cs_mode is None:
            raise NotFound("Arch or mode for hooked liblary")
        asm = Assembler(target, cs_arch.text, cs_mode.text)
        ftb = FuncTable(target, asm)
        cmpl = Compile(cc, args.target_dir)
        inj = Inject(target, asm)

        # parse included libs
        for lib in lib.find("include").iterfind("lib"):
            kind = inc.attrib.get("kind")
            if kind == "system":
                inc_value = f"#include <{inc}>"
            elif kind == "local":
                inc_value = f'#include "{inc}"'
            else:
                raise Wrong("Kind of include lib")
            cmpl.include_lib(inc_value)

        # parse included funcs
        for inc in lib.find("include").iterfind("func"):
            kind = inc.attrib.get("kind")
            name = inc.text
            if kind == "import":
                addr = ftb.load_import(name)
            elif kind == "symbol":
                addr = ftb.load_symbol(name)
            else:
                raise Wrong("Kind of include func")
            proto = inc.attrib.get("proto")
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
        segm_addr = target.get_section(".shook").virtual_address
        funcs_info = cmpl.compile_transl(segm_addr)

        logging.info("Patching the hook(s)...")
        content = []
        for func in funcs_info.values():
            arr = func["content"]
            offset = func["offset"] + segm_addr
            content += asm.patch_sub_values(arr, offset)
        inj.shook_sect_fill(content)

        for to_hook in lib.iterfind("hook"):
            fnc_name = to_hook.attrib["name"]
            logging.info(f"Hooking {fnc_name}")

            fnc_offset = target.get_static_symbol(fnc_name).value  # address of func
            # offset of func in created section
            payl_offset = funcs_info[fnc_name]["offset"]
            inj.hook(fnc_name, fnc_offset, payl_offset)

        target.write((args.output_dir / lib.attrib["path"]).name)
    logging.info("Lib(s) patched")


if __name__ == "__main__":
    main()
