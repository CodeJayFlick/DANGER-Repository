import os
import sys
from typing import Dict, List, Tuple

class SleighCompileLauncher:
    FILE_IN_DEFAULT_EXT = ".slaspec"
    FILE_OUT_DEFAULT_EXT = ".sla"

    SLASPEC_FILTER = lambda pathname: pathname.name.endswith(FILE_IN_DEFAULT_EXT)

    def __init__(self):
        pass

    @staticmethod
    def launch(layout: str, args: List[str]) -> int:
        try:
            application_configuration = ApplicationConfiguration()
            Application.initialize_application(layout, configuration)
            return run_main(args)
        except JDOMException as e:
            print(f"JDOM Exception: {e}")
            return 1
        except IOException as e:
            print(f"I/O Error: {e}")
            return 1
        except RecognitionException as e:
            print(f"Parsing Error: {e}")
            return 1

    @staticmethod
    def run_main(args: List[str]) -> int:
        retval = 0
        file_in = None
        file_out = None
        preprocs = {}

        SleighCompile.yydebug = False
        all_mode = False

        if len(args) < 1:
            print("Usage: sleigh [options...] [<infile.{}> [<outfile.{})] | -a <directory-path>]".format(FILE_IN_DEFAULT_EXT, FILE_OUT_DEFAULT_EXT))
            return 2

        for i in range(len(args)):
            if args[i].startswith("-"):
                if args[i][1:] == "i":
                    inject_options_from_file(args, i + 1)
                elif args[i][1:] == "D":
                    preproc = args[i][2:]
                    pos = preproc.find("=")
                    name = preproc[:pos]
                    value = preproc[pos + 1:]
                    preprocs[name] = value
                elif args[i][1:] in ["u", "t", "e", "f", "l", "c", "n", "o", "s"]:
                    if args[i][1:] == "u":
                        unnecessary_pcode_warning = True
                    elif args[i][1:] == "t":
                        dead_temp_warning = True
                    elif args[i][1:] == "e":
                        enforce_local_key_word = True
                    elif args[i][1:] == "f":
                        unused_field_warning = True
                    elif args[i][1:] == "l":
                        lenient_conflict = False
                    elif args[i][1:] == "c":
                        all_collision_warning = True
                    elif args[i][1:] == "n":
                        all_nop_warning = True
                    elif args[i][1:] == "o":
                        large_temporary_warning = True
                else:
                    print(f"Unknown option: {args[i]}")
                    return 1

        if all_mode and i < len(args) - 2:
            print("Missing input directory path")
            return 1

        compiler = SleighCompile()
        compiler.set_all_options(preprocs, unnecessary_pcode_warning, lenient_conflict,
                                 all_collision_warning, all_nop_warning, dead_temp_warning,
                                 unused_field_warning, enforce_local_key_word,
                                 large_temporary_warning)

        if i < len(args):
            file_in = args[i]
            if i + 1 < len(args):
                file_out = args[i + 1]

        base_name = os.path.splitext(file_in)[0] + FILE_IN_DEFAULT_EXT
        if file_out is None:
            file_out = base_name
        else:
            base_out_name = os.path.splitext(file_out)[0]
            file_out = base_out_name + FILE_OUT_DEFAULT_EXT

        return compiler.run_compilation(file_in, file_out)

    @staticmethod
    def inject_options_from_file(args: List[str], index: int) -> Tuple[int, str]:
        if index >= len(args):
            print("Missing options input file name")
            return 1, None

        try:
            with open(args[index]) as f:
                for line in f.readlines():
                    args.insert(index + 1, line.strip())
                return 0, "Options injected successfully"
        except FileNotFoundError:
            print(f"File not found: {args[index]}")
            if os.environ.get("DEV_MODE", None) == "True":
                print("Eclipse language module must be selected and 'gradle prepdev' previously run")
            return 1, None
