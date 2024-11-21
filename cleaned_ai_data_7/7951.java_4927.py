import os
from datetime import datetime

class PdbUniversalAnalyzer:
    def __init__(self):
        self.name = "PDB Universal"
        self.description = """Platform-independent PDB analyzer (No XML support).
            NOTE: still undergoing development, so options may change.
            PDB Symbol Server searching is configured in Edit -> Symbol Server Config."""
        self.default_enablement = True
        self.developer_mode = False

    def added(self, program, address_set_view, task_monitor, message_log):
        if not set.contains(program.get_memory()):
            return False
        
        pdb_file = None
        if self.do_force_load and self.force_load_file:
            if not os.path.exists(self.force_load_file):
                log_failure("Force-load PDB file does not exist: " + str(self.force_load_file), message_log)
                return False
            pdb_file = self.force_load_file
        
        elif search_remote_locations:
            pdb_file = find_pdb(self, program, task_monitor)

        if pdb_file is None:
            # warnings have already been logged
            return False

        print("================================================================================")
        print(str(datetime.now()) + "\n")
        print(f"Ghidra Version: {Application.get_application_version()}")
        print(self.name)
        print(self.description)
        print(f"PDB Filename: {pdb_file}\n")

        try:
            with PdbParser().parse(pdb_file, self.pdb_reader_options) as pdb:
                task_monitor.set_message("PDB: Parsing " + str(pdb_file) + "...") 
                pdb.deserialize(task_monitor)
                applicator = PdbApplicator(pdb_file, pdb)
                applicator.apply_to(program, program.get_data_type_manager(), program.get_image_base(),
                    self.pdb_applicator_options, task_monitor, message_log)

        except (PdbException, IOException) as e:
            log_failure("Issue processing PDB file: " + str(pdb_file) + ": " + str(e), message_log)
            return False

        return True

    def can_analyze(self, program):
        return PdbAnalyzerCommon.can_analyze_program(program)

    def register_options(self, options, program):
        if self.developer_mode:
            options.register_option("Do Force-Load", bool(False), None,
                "If checked, uses the 'Force Load' file without validation.")
            options.register_option("Force-Load FilePath", str(DEFAULT_FORCE_LOAD_FILE), None,
                "This file is force-loaded if the 'Do Force-Load' option is checked")
        options.register_option(PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS, bool(self.search_remote_locations),
            None, PdbAnalyzerCommon.OPTION_DESCRIPTION_SEARCH_REMOTE_LOCATIONS)

    def options_changed(self, options, program):
        self.do_force_load = options.get_bool("Do Force-Load", self.do_force_load)
        self.force_load_file = options.get_str("Force-Load FilePath", self.force_load_file)
        
        self.search_remote_locations = options.get_bool(
            PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS, self.search_remote_locations)

    def log_failure(self, msg, message_log):
        message_log.append_msg(self.name, msg)
        message_log.append_msg(self.name, "Skipping PDB processing")
        message_log.set_status(msg)

PdbUniversalAnalyzer.set_pdb_file_option = lambda program, pdb_file: PdbAnalyzerCommon.set_pdb_file_option("PDB Universal", program, pdb_file)
PdbUniversalAnalyzer.set_allow_remote_option = lambda program, allow_remote: PdbAnalyzerCommon.set_allow_remote_option("PDB Universal", program, allow_remote)

