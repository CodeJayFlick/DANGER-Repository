class PdbAnalyzer:
    NAME = "PDB MSDIA"
    DEFAULT_ENABLEMENT = not PdbUniversalAnalyzer.DEFAULT_ENABLEMENT
    DESCRIPTION = """PDB Analyzer.
Requires MS DIA-SDK for raw PDB processing (Windows only).
Also supports pre-processed XML files.
PDB Symbol Server searching is configured in Edit -> Symbol Server Config."""
    ERROR_TITLE = "Error in PDB Analyzer"

    def __init__(self):
        super().__init__(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER)
        self.setDefaultEnablement(DEFAULT_ENABLEMENT)
        self.setPriority(AnalysisPriority.FORMAT_ANALYSIS.after())
        self.setSupportsOneTimeAnalysis()

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog):
        tx_id = program.getCurrentTransaction().getID()
        if tx_id == self.last_transaction_id:
            return False
        self.last_transaction_id = tx_id

        if not set.contains(program.getMemory()):
            return False

        if PdbParser.isAlreadyLoaded(program):
            if not PdbUniversalAnalyzer.isEnabled(program):  # yield to other analyzer complaining
                log.appendMsg(self.getName(), "Skipping PDB analysis since it has previously run.")
                log.appendMsg(self.getName(),
                              ">> Clear 'PDB Loaded' program property or use Load PDB action if additional PDB processing required.")
            return True

        if PdbUniversalAnalyzer.isEnabled(program):
            log.appendMsg(self.getName(),
                          f"Stopped: Cannot run with {PdbUniversalAnalyzer.NAME} Analyzer enabled")
            return False

        pdb_file = PdbAnalyzerCommon.find_pdb(self, program, self.search_remote_locations, monitor)
        if pdb_file is None:
            # warnings have already been logged
            return False

        auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
        return parse_pdb(pdb_file, program, auto_analysis_manager, monitor, log)

    def parse_pdb(self, pdb: File, program: Program, manager: AutoAnalysisManager, monitor: TaskMonitor,
                  log: MessageLog):
        data_type_manager_service = manager.get_data_type_manager_service()
        parser = PdbParser(pdb, program, data_type_manager_service, True, False, monitor)

        try:
            parser.parse()
            parser.open_data_type_archives()
            parser.apply_to(log)
            return True
        except PdbException as e:
            log.appendMsg(self.getName(), str(e))
            log.setStatus(str(e))
            return False
        except CancelledException:
            return False
        except Exception as e:
            msg = str(e) if not isinstance(e, str) else e
            Msg.showError(self, None, self.ERROR_TITLE, msg, e)
            return False

    def can_analyze(self, program: Program):
        return PdbAnalyzerCommon.can_analyze_program(program)

    def register_options(self, options: Options, program: Program):
        options.register_option(PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS,
                                self.search_remote_locations, None,
                                PdbAnalyzerCommon.OPTION_DESCRIPTION_SEARCH_REMOTE_LOCATIONS)
