import os
from typing import Dict, List

class OpenDeclarations:
    def __init__(self, project: str):
        self.project = project
        self.symbol_map: Dict[str, int] = {}

    def set_project(self, new_project: str) -> None:
        self.project = new_project

    def open(self, filename: str, lineNumber: int) -> bool:
        return self.open_single_file_at_line_number(filename, lineNumber)

    def open(self, symbol_name: str) -> bool:
        if symbol_name in self.symbol_map:
            EclipseMessageUtils.info(f"Re-using editor for symbol: {symbol_name}")
            self.open_file_from_map(symbol_name)
            return True

        EclipseMessageUtils.info("Searching index for symbol:")
        c_project = CoreModel().get_default().get_c_model().get_c_project(self.project)
        i_index_manager = CCorePlugin().get_index_manager()

        try:
            i_index = i_index_manager.get_index(c_project)

            self.wait_for_index_initialization(i_index)

            i_index.acquire_read_lock()
            bindings = i_index.find_bindings(Pattern.compile(symbol_name), False, IndexFilter.ALL, NullProgressMonitor())
            EclipseMessageUtils.info(f"Found {len(bindings)} bindings for symbol")
            for binding in bindings:
                names = i_index.find_names(binding, IIndex.FIND_DEFINITIONS)
                for name in names:
                    self.symbol_map[name] = 0

        except Exception as e:
            EclipseMessageUtils.error("Unexpected exception searching C index:", str(e))
            return False
        finally:
            if i_index is not None:
                i_index.release_read_lock()

    def wait_for_index_initialization(self, i_index: IIndex) -> None:
        for _ in range(2):
            try:
                i_index.acquire_read_lock()
                all_files = i_index.get_all_files()
                if len(all_files) == 0:
                    EclipseMessageUtils.info("C Index is not yet initialized--waiting...")
                    i_index.release_read_lock()
                    time.sleep(1)
                else:
                    break
            except InterruptedException as e:
                pass

    def open_single_file(self, location: IASTFileLocation, function_name: str) -> None:
        path_to_fix = location.get_filename()
        project_name = self.project
        index = path_to_fix.find(project_name)
        if index == -1:
            EclipseMessageUtils.error(f"Error opening the file containing {path_to_fix}")
            return

        relative_path = path_to_fix[index:]
        final_i_path = os.path.join(self.project, relative_path).removeprefix(self.project + "/")
        offset = location.get_node_offset()
        length = location.get_node_length()
        f_name = function_name
        Display().async_exec(lambda: self.open_file(final_i_path, offset, length))

    def open_multiple_file_dialog(self, function_name: str) -> None:
        dialog = ElementSelectionDialog(Display())
        configure_dialog(dialog, function_name)
        final_f_name = function_name

        Display().async_exec(lambda: EclipseMessageUtils.get_workbench_page().get_workbench_window().force_active()
                              and dialog.open() or
                             for result in dialog.result():
                                 if isinstance(result, IndexTypeInfo):
                                     reference = (result).resolved_reference
                                     i_path = reference.path.removeprefix(self.project + "/")
                                     file = self.project.file(i_path)
                                     try:
                                         marker = file.create_marker(IMarker.TEXT)
                                         marker.set_attribute(IMarker.CHAR_START, reference.offset)
                                         marker.set_attribute(IMarker.CHAR_END, reference.offset + reference.length)
                                         IDE().open_editor(EclipseMessageUtils.get_workbench_page(), marker)
                                         self.symbol_map[final_f_name] = 0
                                     except CoreException as e:
                                         EclipseMessageUtils.error("Error opening file chosen from selection dialog", str(e))

    def open_single_file_at_line_number(self, relative_filename: str, line_number: int) -> None:
        final_i_path = os.path.join(self.project, relative_filename).removeprefix(self.project + "/")
        Display().async_exec(lambda: self.open_file(final_i_path, 0, line_number))

    def configure_dialog(self, dialog: ElementSelectionDialog, function_name: str) -> None:
        dialog.set_title("Open Type Dialog Title")
        dialog.set_message("Open Type Dialog Message")
        dialog.set_settings(classname)
        if len(function_name) > 0 and len(function_name) < 80:
            dialog.set_filter(function_name, True)

    def open_file_from_map(self, function_name: str) -> None:
        final_marker = self.symbol_map[function_name]
        Display().async_exec(lambda: IDE().open_editor(EclipseMessageUtils.get_workbench_page(), marker)
                              and EclipseMessageUtils.get_workbench_page().get_workbench_window().force_active())

    def open_file(self, i_path: str, offset: int, length: int) -> None:
        file = self.project.file(i_path)
        try:
            marker = file.create_marker(IMarker.TEXT)
            marker.set_attribute(IMarker.CHAR_START, offset)
            marker.set_attribute(IMarker.CHAR_END, offset + length)
            IDE().open_editor(EclipseMessageUtils.get_workbench_page(), marker)
            EclipseMessageUtils.get_workbench_page().get_workbench_window().force_active()
        except CoreException as e:
            EclipseMessageUtils.error("Error opening the file", str(e))
