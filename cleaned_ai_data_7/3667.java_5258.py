import os
from tkinter import filedialog
from tkinter.messagebox import showerror, askyesno
from typing import List, Dict

class ExportToHeaderAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Export Data Types", plugin.get_name())

        set_popup_menu_data(new MenuData(["Export C Header..."], None, "VeryLast"))
        set_enabled(True)

    @property
    def is_enabled_for_context(self) -> bool:
        if not isinstance(context, DataTypesActionContext):
            return False

        context_object = context.get_context_object()
        gtree = GTree(context_object)
        selection_paths = gtree.get_selection_paths()

        for path in selection_paths:
            node = GTreeNode(path[-1])
            if not self.is_valid_node(node):
                return False
        return True

    def is_valid_node(self, node) -> bool:
        if isinstance(node, CategoryNode):
            category_node = node
            return category_node.get_enabled()
        elif isinstance(node, DataTypeNode):
            return True
        else:
            return False

    @property
    def action_performed(self) -> None:
        dt_action_context = DataTypesActionContext(context)
        gtree = GTree(dt_action_context.get_context_object())
        program = dt_action_context.get_program()

        if not program:
            showerror("Archive Export Failed", "A suitable program must be open and activated before an archive export may be performed.")
            return

        if askyesno("Confirm Archive Export", f"Export selected archive(s) using program {program.name}'s compiler specification?") != 1:
            return
        self.export_to_c(gtree, program.get_data_type_manager())

    def export_to_c(self, gtree: GTree, data_type_mgr: DataTypeManager):
        classes = ClassSearcher().get_classes(AnnotationHandler)
        list_ = []
        for clazz in classes:
            if clazz == DefaultAnnotationHandler:
                continue
            try:
                constructor = clazz.get_constructor(())
                obj = constructor.newInstance()
                list_.append(obj)
            except Exception as e:
                showerror("Export Data Types", f"Error creating {clazz.name}\n{e}")
        handler = None
        if len(list_) > 0:
            list_.insert(0, DefaultAnnotationHandler())
            AnnotationHandlerDialog(dlg).show()
            if not dlg.was_successful():
                return
            handler = dlg.get_handler()
        else:
            handler = DefaultAnnotationHandler()

        paths = gtree.get_selection_paths()
        managers_to_data_types_map: Dict[DataTypeManager, List[DataType]] = {}

        for path in paths:
            self.add_to_manager(path, managers_to_data_types_map)

        file_chooser = GhidraFileChooser(gtree)
        set_file_filter(file_, handler.get_language_name() + " Files")

        entry_set = managers_to_data_types_map.items()
        for entry in entry_set:
            data_type_mgr = entry[0]
            file = self.get_file(gtree, file_, data_type_mgr, handler)

            if not file:
                return

            list_ = entry[1]
            TaskLauncher(Task("Export Data Types", True, False, True), gtree).start()

    def add_to_manager(self, path: TreePath, managers_to_data_types_map: Dict):
        last = path[-1]

        if isinstance(last, DataTypeNode):
            node = last
            data_type = node.get_data_type()
            data_type_mgr = data_type.get_data_type_manager()

            list_ = managers_to_data_types_map.get(data_type_mgr)
            if not list_:
                list_ = []
                managers_to_data_types_map[data_type_mgr] = list_
            list_.append(data_type)

        elif isinstance(last, CategoryNode):
            node = last
            children = node.get_children()
            for cnode in children:
                self.add_to_manager(cnode.get_tree_path(), managers_to_data_types_map)
        else:
            return

    def get_file(self, gtree: GTree, file_chooser: GhidraFileChooser, data_type_mgr: DataTypeManager, handler):
        file_chooser.set_title(f"Select File For Export: {data_type_mgr.name}")
        file_chooser.set_selected_file(None)

        default_extension_suffix = ".h"

        last_dir_selected = Preferences.get(LAST_DATA_TYPE_EXPORT_DIRECTORY)
        if last_dir_selected:
            file = os.path.join(last_dir_selected, "")
            if os.path.exists(file):
                file_chooser.set_current_directory(os.path.dirname(file))
            else:
                return None

        file_chooser.rescan_current_directory()  # pick up any recently added archives
        current_directory = file_chooser.get_current_directory()
        new_file = os.path.join(current_directory, f"{data_type_mgr.name}{default_extension_suffix}")
        file_chooser.set_selected_file(new_file)

        if not file_chooser.get_selected_file():
            return None

        has_known_extension = False
        path = file_chooser.get_selected_file().get_path()

        extensions = handler.get_file_extensions()
        for extension in extensions:
            if path.lower().endswith("." + extension):
                has_known_extension = True
                break

        if not has_known_extension and default_extension_suffix:
            new_file = os.path.join(os.path.dirname(new_file), f"{os.path.basename(new_file)}{default_extension_suffix}")
            file_chooser.set_selected_file(new_file)

        if os.path.exists(file_chooser.get_selected_file()):
            if askyesno("Overwrite Existing File?", "Do you want to overwrite the existing file?") != 1:
                return None

        Preferences.set(LAST_DATA_TYPE_EXPORT_DIRECTORY, new_file)
        return file_
