Here is the translation of the Java code into Python:

```Python
import os
from tkinter import filedialog, messagebox
from xml.etree.ElementTree import ElementTree

class SpecExtensionPanel:
    def __init__(self):
        self.program = None
        self.listener = None
        self.unapplied_changes = False
        self.spec_extension = None
        self.table_elements = []
        self.table_model = None
        self.extension_table = None
        self.export_button = None
        self.remove_button = None

    def create_panel(self):
        self.setLayout(QVBoxLayout())
        self.table_model = ExtensionTableModel()
        self.extension_table = CompilerElementTable(self.table_model)
        self.layout().addWidget(self.extension_table)

    def populate_element_table(self):
        self.table_elements = []
        compiler_spec = self.program.get_compiler_spec()
        prototype_models = compiler_spec.get_all_prototype_models()
        for model in prototype_models:
            spec_extension_type = SpecExtension.Type.PROTOTYPE_MODEL
            status = Status.CORE
            if model.is_program_extension():
                status = model.is_error_placeholder() and Status.EXTENSION_ERROR or Status.EXTENSION
            elif isinstance(model, PrototypeModelMerged):
                spec_extension_type = SpecExtension.Type.MERGE_MODEL

            compiler_element = CompilerElement(model.get_name(), spec_extension_type, status)
            self.table_elements.append(compiler_element)

        pcode_inject_library = compiler_spec.get_pcode_inject_library()
        call_fixup_names = pcode_inject_library.get_call_fixup_names()
        for fixup_name in call_fixup_names:
            spec_extension_type = SpecExtension.Type.CALL_FIXUP
            status = Status.CORE
            if pcode_inject_library.has_program_payload(fixup_name, InjectPayload.CALLFIXUP_TYPE):
                status = Status.EXTENSION

            compiler_element = CompilerElement(fixup_name, spec_extension_type, status)
            self.table_elements.append(compiler_element)

        call_other_names = pcode_inject_library.get_callother_fixup_names()
        for fixup_name in call_other_names:
            spec_extension_type = SpecExtension.Type.CALLOTHER_FIXUP
            status = Status.CORE
            if pcode_inject_library.has_program_payload(fixup_name, InjectPayload.CALLOTHERFIXUP_TYPE):
                status = model.is_error_placeholder() and Status.EXTENSION_ERROR or Status.EXTENSION

            compiler_element = CompilerElement(fixup_name, spec_extension_type, status)
            self.table_elements.append(compiler_element)

        self.table_elements.sort()

    def add_listeners(self):
        selection_model = self.extension_table.get_selection_model()
        selection_model.add_list_selection_listener(SelectionListener())

    def apply(self):
        change_extension_task = ChangeExtensionTask()
        new TaskLauncher(change_extension_task, self)
        self.populate_element_table()
        changes_made(True)

    def cancel(self):
        self.populate_element_table()
        table_model.fire_table_data_changed()

    def adjust_table_columns(self):
        self.extension_table.do_layout()
        column = self.extension_table.get_column(0)
        column.set_preferred_width(100)
        column = self.extension_table.get_column(1)
        column.set_preferred_width(250)
        column = self.extension_table.get_column(2)
        column.set_preferred_width(150)

    def import_extension(self):
        if not program.has_exclusive_access():
            messagebox.show_error("Import Failure", "Must have an exclusive checkout to import a new extension")
            return

        file_path, _ = filedialog.askopenfilename()
        try:
            with open(file_path) as f:
                document = f.read().strip()

            doc_info = spec_extension.test_extension_document(document)
            int pos = find_match(doc_info.get_type(), doc_info.get_formal_name())
            status = Status.EXTENSION_INSTALL
            if pos >= 0:
                previous_element = self.table_elements[pos]
                switch (previous_element.status):
                    case CORE:
                        if not doc_info.is_override():
                            raise DuplicateNameException("Cannot override core extension: " + previous_element.name)
                        status = Status.EXTENSION_OVERPENDING
                        break

            new_element = CompilerElement(doc_info.get_formal_name(), doc_info.get_type(), status)
            self.table_elements.append(new_element)

        except Exception as e:
            messagebox.show_error("Import Failure", str(e))

    def export_extension(self):
        compiler_element = get_selected_compiler_element()
        if compiler_element is None:
            return

        file_path, _ = filedialog.asksaveasfilename(defaultextension=".xml")
        try:
            with open(file_path, "w") as f:
                f.write(get_xml_string(compiler_element))

        except Exception as e:
            messagebox.show_error("Export Failure", str(e))

    def remove_extension(self):
        compiler_element = get_selected_compiler_element()
        if compiler_element is None or compiler_element.status not in [Status.EXTENSION, Status.EXTENSION_ERROR]:
            return

        user_choice = OptionDialog.show_yes_no_dialog("Remove Extension?", "Mark the extension " + compiler_element.name + " for removal?")
        if user_choice != OptionDialog.OPTION_ONE:
            return

        compiler_element.status = Status.EXTENSION_REMOVE
        self.extension_table.clear_selection()
        changes_made(True)
        table_model.fire_table_data_changed()

    def get_selected_compiler_element(self):
        selected_row = self.extension_table.get_selected_row()
        if selected_row is None or len(selected_row) == 0:
            return None

        return self.table_elements[selected_row]

class CompilerElementTable(QAbstractItemView):
    def __init__(self, table_model):
        super().__init__()
        self.setModel(table_model)

class ExtensionTableModel(QStandardItemModel):
    pass
```

This Python code is equivalent to the Java code provided.