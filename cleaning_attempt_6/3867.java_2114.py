from tkinter import *
import tkinter.messagebox as tkmb

class StorageAddressEditorDialog:
    def __init__(self, program, service, storage, variable_data):
        self.variable_data = variable_data
        self.model = StorageAddressModel(program, storage, self)
        current_dtype = variable_data.get_formal_dtype()
        previous_dtype = current_dtype.copy()
        set_current_dtype(current_dtype)
        help_location = HelpLocation("FunctionPlugin", "Edit_Parameter_Storage")
        work_panel = build_main_panel(service)
        ok_button = Button(self.root, text="OK", command=self.ok_callback)
        cancel_button = Button(self.root, text="Cancel", command=self.cancel_callback)
        self.data_changed()

    def ok_callback(self):
        if varnode_table.is_editing():
            return
        if not set_current_dtype(current_dtype):
            status_text.set("Invalid data type")
            return
        cancelled = False
        close()

    def get_storage(self):
        return model.get_storage()

    def build_main_panel(self, service):
        panel = Frame()
        panel.pack(fill=BOTH)
        info_panel = self.build_info_panel(service)
        table_panel = self.build_table_panel()
        panel.grid(row=0, column=0, sticky=NSEW)
        info_panel.grid(row=1, column=0, sticky=NSEW)
        table_panel.grid(row=2, column=0, sticky=NSEW)

    def build_info_panel(self, service):
        panel = Frame()
        panel.pack(fill=BOTH)
        label = Label(panel, text="Datatype:")
        self.data_type_edit_component = StringVar(value=current_dtype.name())
        entry = Entry(panel, textvariable=self.data_type_edit_component)
        button = Button(panel, text="...", command=lambda: self.show_data_types(service))
        size_label = Label(panel, text=str(size))
        current_size_label = Label(panel, text="")
        panel.pack(fill=BOTH)

    def build_table_panel(self):
        table = Table()
        varnode_table_model = VarnodeTableModel(model)
        selection_listener = ListSelectionListener()
        table.selection_model().add_list_selection_listener(selection_listener)
        for i in range(10):  # number of rows
            row_data = []
            for j in range(2):  # number of columns
                row_data.append(StringVar(value=""))
            varnode_table_model.set_varnodes(row_data)

    def build_button_panel(self):
        panel = Frame()
        add_button = Button(panel, text="Add", command=lambda: self.add_varnode())
        remove_button = Button(panel, text="Remove", command=lambda: self.remove_varnodes())
        up_button = Button(panel, text="Up", command=lambda: self.move_selected_varnode_up())
        down_button = Button(panel, text="Down", command=lambda: self.move_selected_varnode_down())

    def data_changed(self):
        update_data_type()
        update_current_size()
        update_status_text()
        update_ok_button()

class StorageAddressModel:
    def __init__(self, program, storage, dialog):
        self.program = program
        self.storage = storage
        self.dialog = dialog

    def get_storage(self):
        return self.storage

    # other methods...

class VarnodeTableModel:
    def __init__(self, model):
        self.model = model

    def set_varnodes(self, varnode_list):
        for i in range(len(varnode_list)):
            row_data.append(StringVar(value=varnode_list[i]))

# other classes and functions...
