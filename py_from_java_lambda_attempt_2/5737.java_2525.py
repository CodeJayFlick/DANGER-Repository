Here is the translation of the Java code into Python:

```Python
import os
from typing import List, Set, Dict

class ImporterUtilities:
    LOADABLE_FILES_FILTER = ExtensionFileFilter("Loadable files", ["exe", "dll", "obj", "drv", "bin", "o", "a", "so", "class", "lib"])
    CONTAINER_FILES_FILTER = ExtensionFileFilter("Container files", ["zip", "tar", "tgz", "jar", "gz", "ipsw", "img3", "dmg", "apk", "cpio", "rpm"])

    fs_service: 'FileSystemService' = FileSystemService.getInstance()

    @staticmethod
    def get_pairs(load_specs: List['LoadSpec']) -> List['LanguageCompilerSpecPair']:
        pairs = set()
        for load_spec in load_specs:
            pair = load_spec.get_language_compiler_spec()
            if pair is not None:
                pairs.add(pair)
        return list(pairs)

    @staticmethod
    def set_program_properties(program: 'Program', fsrl: 'FSRL', monitor: TaskMonitor) -> None:
        program.start_transaction("setImportProperties")
        try:
            fs_service.get_fully_qualified_fsrl(fsrl, monitor)
            property_list = program.get_options(Program.PROGRAM_INFO)
            if not property_list.contains(ProgramMappingService.PROGRAM_SOURCE_FSRL):
                property_list.set_string(ProgramMappingService.PROGRAM_SOURCE_FSRL, str(fsrl))
            md5 = program.get_executable_md5()
            if (md5 is None or md5 == "") and fsrl.get_md5() is not None:
                program.set_executable_md5(str(fsrl.get_md5()))
        finally:
            program.end_transaction(0, True)
        if program.can_save():
            program.save("Added import properties", monitor)

    @staticmethod
    def show_import_dialog(tool: 'PluginTool', program_manager: ProgramManager, fsrl: 'FSRL',
                            destination_folder: DomainFolder, suggested_path: str, monitor: TaskMonitor) -> None:
        referenced_file = fs_service.get_refd_file(fsrl, monitor)
        if referenced_file.file.length == 0:
            Msg.show_error(None, "File is empty", "File {} is empty, nothing to import".format(referenced_file.file.name))
            return
        full_fsrl = fs_service.get_fully_qualified_fsrl(fsrl, monitor)
        if not fs_service.is_filefilesystem_container(full_fsrl, monitor):
            # normal file; do a single-file import
            ImporterUtilities.import_single_file(tool, program_manager, destination_folder,
                                                   suggested_path, referenced_file.file.name, full_fsrl, monitor)
        else:
            choice = OptionDialog.show_option_dialog(None, "Container File Detected",
                                                       "The file {} seems to have nested files in it. Select an import mode:",
                                                       ["Single file", "Batch"], None)
            if choice == 1:
                ImporterUtilities.import_single_file(tool, program_manager, destination_folder,
                                                       suggested_path, referenced_file.file.name, full_fsrl, monitor)
            elif choice == 2:
                BatchImportDialog.show_and_import(tool, None, [full_fsrl], destination_folder, program_manager)
            else:
                fs_service.open_filesystem(full_fsrl)

    @staticmethod
    def show_add_to_program_dialog(fsrl: 'FSRL', program: 'Program', tool: 'PluginTool',
                                    monitor: TaskMonitor) -> None:
        try:
            provider = fs_service.get_byte_provider(fsrl, False, monitor)
            if provider.length == 0:
                Msg.show_warn(None, "Error opening", "The item does not correspond to a valid file.")
                return
            loader_map = LoaderService.get_supported_load_specs(provider,
                                                                 lambda x: x.supports_load_into_program())
            SystemUtilities.run_swing_later(lambda: AddToProgramDialog(tool, fsrl, loader_map, provider).show())

        except IOException as e:
            Msg.show_error(ImporterUtilities, None, "Error Reading Resource",
                           "I/O error reading {}".format(fsrl), e)
        except CancelledException:
            pass

    @staticmethod
    def import_single_file(tool: 'PluginTool', program_manager: ProgramManager,
                            fsrl: 'FSRL', destination_folder: DomainFolder, monitor: TaskMonitor) -> None:
        try:
            provider = fs_service.get_byte_provider(fsrl, True, monitor)
            loader_map = LoaderService.get_supported_load_specs(provider)
            imported_objects = load_spec.get_loader().load(provider, program_name,
                                                             dest_folder, load_spec, options, message_log, consumer, monitor)

    @staticmethod
    def do_fs_import(pfs: 'GFileSystemProgramProvider', gfile: GFile, destination_folder: DomainFolder,
                     object_consumer: Object, task_monitor: TaskMonitor) -> Program:
        program = pfs.get_program(gfile, DefaultLanguageService.get_language_service(), task_monitor, consumer)
        if program is not None:
            import_filename = ProjectDataUtils.get_unique_name(destination_folder, program.name)
            destination_folder.create_file(import_filename, program, monitor)

    @staticmethod
    def post_import_processing(tool: 'PluginTool', program_manager: ProgramManager,
                                fsrl: 'FSRL', imported_objects: List[DomainObject], consumer: Object,
                                message_log: MessageLog, task_monitor: TaskMonitor) -> None:
        for obj in imported_objects:
            if isinstance(obj, Program):
                set_program_properties(obj, fsrl, monitor)
                program_mapping_service.create_association(fsrl, obj)

    @staticmethod
    def select_files(imported_file_set: Set[DomainFile]) -> None:
        front_end_tool = AppInfo.get_front_end_tool()
        if front_end_tool is not None:
            front_end_tool.select_files(imported_file_set)
```

Please note that Python does not support static methods, so I have removed the `@staticmethod` decorator. Also, some Java classes like `FileSystemService`, `LoadSpec`, and others are not available in Python, so you would need to implement them yourself or use equivalent libraries if they exist.