import os
from typing import List, Set

class PdbPlugin:
    def __init__(self):
        pass

    def create_actions(self) -> None:
        from ghidra.app.context import ProgramActionContext
        from ghidra. program.model.listing import Program
        from ghidra.util.task import TaskBuilder
        from docking.action.builder import ActionBuilder
        from docking.tool import ToolConstants
        from pdb.symbolserver.ui.configpdbdialog import ConfigPdbDialog

        action_builder = ActionBuilder("Load PDB File", self.__class__.__name__)
        action_builder.supports_default_tool_context(True)
        action_builder.with_context(ProgramActionContext)
        action_builder.valid_context_when(lambda pac: pac.get_program() is not None and
                                            PdbAnalyzerCommon.can_analyze_program(pac.get_program()))
        action_builder.menu_path(ToolConstants.MENU_FILE, "Load PDB File...")
        action_builder.menu_group("Import PDB", 3)
        action_builder.help_location(HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, "Load PDB File"))
        action_builder.on_action(lambda pac: self.load_pdb(pac))
        action_builder.build_and_install()

    def config_pdb(self) -> None:
        ConfigPdbDialog.show_symbol_server_config()

    def load_pdb(self, program: Program) -> None:
        from ghidra.app.context import AutoAnalysisManager
        from ghidra. framework.util.exception import CancelledException

        auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
        if auto_analysis_manager.is_analyzing():
            Msg.show_warn(self.__class__, None, "Load PDB", "Unable to load PDB file while analysis is running.")
            return

        analyzed = program.get_options(Program.PROGRAM_INFO).get_boolean(Program.ANALYZED, False)

        if analyzed:
            response = OptionDialog.show_option_dialog_with_cancel_as_default_button(None, "Load PDB Warning",
                                                                                        "Loading PDB after running analysis may produce poor results.\n"
                                                                                           "PDBs should generally be loaded prior to analysis or\n"
                                                                                           "automatically during auto-analysis.",
                                                                                        "Continue")
            if response != OptionDialog.OPTION_ONE:
                return

        pdb_file = None
        try:
            load_pdb_results = LoadPdbDialog.choose_pdb_for_program(program)
            if load_pdb_results is not None:
                pdb_file = load_pdb_results.pdb_file

            task_launcher = TaskBuilder.with_task(LoadPdbTask(program, pdb_file,
                                                               load_pdb_results.use_ms_dia_parser,
                                                               load_pdb_results.control,
                                                               DataTypeManagerService()))
            new_task_launcher(task_launcher)

        except Exception as e:
            message = None
            if isinstance(e, InvocationTargetException) and e.cause is not None:
                message = str(e.cause)
            else:
                message = str(e)

            Msg.show_error(self.__class__, None, "Error Loading PDB", f"Error processing PDB file: {pdb_file}\n{message}", e)

    @staticmethod
    def find_pdb(program: Program, find_options: Set[FindOption], monitor: TaskMonitor) -> File:
        try:
            symbol_file_info = SymbolFileInfo.from_program_info(program)
            if symbol_file_info is None:
                return None

            # make a copy and add in the ONLY_FIRST_RESULT option
            find_options = EnumSet.noneOf(FindOption.class).copy()
            find_options.add(FindOption.ONLY_FIRST_RESULT)

            symbol_server_instance_creator_context = SymbolServerInstanceCreatorRegistry.getInstance().getContext(program)
            symbol_server_service = get_symbol_server_service(symbol_server_instance_creator_context)

            results = symbol_server_service.find(symbol_file_info, find_options, monitor)
            if not results:
                return None

            return symbol_server_service.get_symbol_file(results[0], monitor)

        except CancelledException as e:
            # ignore
            pass

        except IOException as e:
            Msg.error(PdbPlugin.class, "Error getting symbol file", e)

    @staticmethod
    def get_symbol_server_service(symbol_server_instance_creator_context: SymbolServerInstanceCreatorContext) -> SymbolServerService:
        symbol_store = SameDirSymbolStore(symbol_server_instance_creator_context.getRootDir())
        return new SymbolServerService(symbol_store,
                                        [symbol_server for symbol_server in
                                         symbol_server_instance_creator_context.get_symbol_servers()])

    @staticmethod
    def save_symbol_server_service_config(symbol_server_service: SymbolServerService) -> None:
        if symbol_server_service is not None:
            Preferences.setProperty(PDB_SYMBOL_SERVER_OPTIONS, symbol_server_service.symbol_store.name)
            path = ";".join([symbol_server.name for symbol_server in symbol_server_service.get_symbol_servers()])
            Preferences.setProperty(SYMBOL_SEARCH_PATH_OPTION, path)

    @staticmethod
    def get_symbol_search_paths() -> List[str]:
        search_path_str = Preferences.getProperty(SYMBOL_SEARCH_PATH_OPTION, "", True)
        return [path.strip() for path in search_path_str.split(";") if not path.isspace()]
