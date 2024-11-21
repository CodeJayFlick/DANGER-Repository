class DataTypePreviewPlugin:
    def __init__(self):
        self.provider = None
        self.model = None
        self.table = None
        self.component = None
        self.current_address = None
        self.go_to_service = None
        self.add_action = None
        self.delete_action = None
        self.data_type_manager = None
        self.active_program = None

    def get_table_model(self):
        return self.model

    def get_go_to_service(self):
        return self.go_to_service

    def get_provider(self):
        return self.provider

    @property
    def root_name(self):
        return "DataTypePreviewer"

    def init(self, tool):
        super().__init__()
        self.go_to_service = tool.get_service(GoToService)
        self.model = DTPPTableModel()
        self.table = DTPPTable(self.model)
        self.component = DTPPSwingConstants(table=self.table)

        data_type_manager = create_layered_data_type_manager()

        for dt in [ByteDataType(), WordDataType(), DWordDataType(), QWordDataType(),
                   FloatDataType(), DoubleDataType(), CharDataType(), TerminatedStringDataType()]:
            add_datatype(data_type_manager, dt)
            self.model.add(DataTypePreview(dt))

    def service_removed(self, interface_class, service):
        if interface_class == GoToService:
            self.go_to_service = None

    def service_added(self, interface_class, service):
        if interface_class == GoToService:
            self.go_to_service = service

    @property
    def is_disposed(self):
        return False

    def dispose(self):
        update_manager.dispose()
        delete_action.dispose()

    def program_activated(self, program):
        super().program_activated(program)
        self.active_program = program
        update_model()

    def location_changed(self, loc):
        if loc:
            current_address = loc.get_byte_address()
        else:
            current_address = None

        update_manager.update()

    @property
    def is_action_enabled(self):
        return len(model) > 0

    def read_config_state(self, save_state):
        names = save_state.names
        for name in names:
            path = save_state.get_string(name)
            if path:
                dt = data_type_manager.get_data_type(CategoryPath(path), name)
                add_datatype(dt)

    @property
    def write_config_state(self):
        return {dt.name: dt.category_path.path() for dt, _ in model}

    def set_action_enabled(self, enabled):
        delete_action.enabled = enabled

    def create_actions(self):
        self.add_action = DockingAction("Add", "DataTypePreviewer")
        self.delete_action = DockingAction("Delete", "DataTypePreviewer")

    @property
    def is_disposed(self):
        return False

class DTPPComponentProvider:
    def __init__(self, tool):
        super().__init__()
        self.tool = tool
        self.component = None

    def get_component(self):
        return self.component

    def component_shown(self):
        update_title()

class DTPPDroppable:
    def __init__(self, drop_target):
        self.acceptable_flavors = [DataTypeTransferable.local_data_type_flavor,
                                   DataTypeTransferable.local_builtin_data_type_flavor]
        self.drop_target_adapter = DropTgtAdapter(self)
        self.drop_target_component = drop_target

class DTPPTableModel:
    def __init__(self):
        self.data = []

    @property
    def model_data(self):
        return self.data

    def add(self, dt):
        if not isValid(dt):
            return False
        if contains(dt):
            tool.status_info("Datatype '{}' already exists.".format(dt.name))
            return False
        data_type_manager.add_datatype(dt)
        self.data.append(DataTypePreview(dt))

    @property
    def name_column_name(self):
        return "Name"

    @property
    def preview_column_name(self):
        return "Preview"

class DTPPTable:
    def __init__(self, model):
        super().__init__()
        self.model = model

    def get_selected_row(self):
        # todo: implement this method
        pass

def create_layered_data_type_manager():
    data_organization = active_program.get_compiler_spec().get_data_organization()
    return StandAloneDataTypeManager("DataTypePreviewer", data_organization)

class DTPPSwingConstants:
    def __init__(self, table):
        super().__init__()
        self.table = table
