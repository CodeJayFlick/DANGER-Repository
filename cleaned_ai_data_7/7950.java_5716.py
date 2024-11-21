class PdbAnalyzerCommon:
    OPTION_DESCRIPTION_SEARCH_REMOTE_LOCATIONS = "If checked, allow searching remote symbol servers for PDB files."
    OPTION_NAME_SEARCH_REMOTE_LOCATIONS = "Search remote symbol servers"

    OPTION_DESCRIPTION_PDB_FILE = "Path to a manually chosen PDB file."
    OPTION_NAME_PDB_FILE = "PDB File"

    @staticmethod
    def can_analyze_program(program):
        executable_format = program.get_executable_format()
        return executable_format is not None and (executable_format.lower().index("pe") != -1)

    @staticmethod
    def set_pdb_file_option(analyzer_name, program, pdb_file):
        options = program.get_options(Program.ANALYSIS_PROPERTIES)
        options.set_file(f"{analyzer_name}.{OPTION_NAME_PDB_FILE}", pdb_file)

    @staticmethod
    def set_allow_remote_option(analyzer_name, program, allow_remote):
        options = program.get_options(Program.ANALYSIS_PROPERTIES)
        options.set_boolean(f"{analyzer_name}.{OPTION_NAME_SEARCH_REMOTE_LOCATIONS}", allow_remote)

    @staticmethod
    def find_pdb(pdb_analyzer, program, allow_remote, monitor):
        symbol_file_info = SymbolFileInfo.from_program_info(program)
        if symbol_file_info is None:
            pdb_analyzer.msg.info("Skipping PDB processing: missing PDB information in program metadata")
            return None

        options = program.get_options(Program.ANALYSIS_PROPERTIES)
        pdb_file_option_name = f"{pdb_analyzer.name}.{OPTION_NAME_PDB_FILE}"

        # check existence first to avoid creating option value
        pdb_file = options.contains(pdb_file_option_name) and options.get_file(pdb_file_option_name, None)

        if pdb_file is None:
            find_opts = FindOption.of(FindOption.ALLOW_REMOTE) if allow_remote else FindOption.NO_OPTIONS
            pdb_file = PdbPlugin.find_pdb(program, find_opts, monitor)
        if pdb_file is None:
            pdb_analyzer.msg.info("Skipping PDB processing: failed to locate PDB file in configured locations")
            if SystemUtilities.is_in_headless_mode():
                pdb_analyzer.msg.info(
                    "Use a script to set the PDB file location. I.e.,\n"
                    f"    {pdb_analyzer.name}.set_pdb_file_option(current_program, new File('/path/to/pdb/file.pdb')) or\n"
                    f"    {PdbUniversalAnalyzer.__name__}.set_pdb_file_option(current_program, new File('/path/to/pdb/file.pdb')); or\n"
                    "Or set the symbol server search configuration using:\n"
                    f"    PdbPlugin.save_symbol_server_service_config(...);\n"
                    " This must be done using a pre-script (prior to analysis).")
            else:
                pdb_analyzer.msg.info(
                    "You may set the PDB \"Symbol Server Config\" \n"
                    "\n using \"Edit->Symbol Server Config\" prior to analysis.\n"
                    "\nIt is important that a PDB is used during initial analysis  "
                    "\nif available.")
        else:
            pdb_analyzer.msg.info(f"PDB analyzer parsing file: {pdb_file}")
            if not pdb_file.is_file():
                pdb_analyzer.msg.error(
                    "Skipping PDB processing: specified file does not exist or is not readable: "
                    f"{pdb_file}"
                )
                return None
        return pdb_file

class SymbolFileInfo:
    @staticmethod
    def from_program_info(program):
        # your code here
        pass

# you might need to define some other classes and functions depending on the usage of this class.
