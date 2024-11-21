Here is your Java code translated into Python:

```Python
class DataSettingsDialog:
    def __init__(self):
        pass

    WIDTH = 350
    HEIGHT = 150
    BOOLEAN_CHOICES = ["yes", "no"]
    NO_CHOICE = ""

    name = None
    data = None
    selection = None
    settings_defs = []
    default_settings = None
    settings = None
    editing_defaults = False

    def __init__(self, program, *args):
        if len(args) == 1:
            self.data = args[0]
            self.name = f"Data Settings for {data.getDisplayName()}"
        elif len(args) == 2 and isinstance(args[0], Program) and isinstance(args[1], Data):
            self.program = program
            self.data = data
            self.name = "Default Data Settings"
        else:
            raise ValueError("Invalid arguments")

    def get_settings_table(self):
        return None

    def dispose(self):
        pass

    @property
    def has_settings(self):
        return len(self.settings_defs) > 0

    def construct_title(self):
        if self.selection is not None:
            return "Common Settings for Selected Data"
        name_buf = StringBuffer()
        if self.data is None:
            name_buf.append("Default ")
        elif isinstance(self.dt, Composite):
            name_buf.append(dt.getDisplayName())
            name_buf.append("(")
            name_buf.append(dt.getParent().getDisplayName())
            name_buf.append('. ')
            field_name = dt.getComponentIndex(data).getFieldName()
            if field_name is None:
                field_name = dt.getDefaultFieldName()
            name_buf.append(field_name)
        else:
            name_buf.append(dt.getDisplayName())
            name_buf.append(" Settings")
        if self.data is not None and self.data.getMinAddress() is not None:
            name_buf.append(f" at {self.data.getMinAddress().toString()}")
        return name_buf.toString()

    def build_panel(self):
        pass

    @property
    def settings_table_model(self):
        return None

    def get_settings_table_model(self):
        if self.selection is not None or self.editing_defaults:
            return SettingsTableModel(self.settings_defs)
        else:
            return None

    class CommonSettingsAccumulator(Task):
        cancelled = False
        defs_array = []

        @property
        def has_next(self):
            pass

        def run(self, monitor):
            if isinstance(selection, InteriorSelection):
                self.accumulate_interior_settings_definitions(monitor)
            else:
                self.accumulate_data_settings_definitions(monitor)

    class SettingsTableModel(AbstractSortedTableModel[SettingsRowObject]):
        rows = []

        @property
        def model_data(self):
            return self.rows

        def __init__(self, settings_defs):
            for sd in settings_defs:
                self.rows.append(SettingsRowObject(sd))

    class SettingsEditor(AbstractCellEditor, TableCellEditor):
        ENUM = 0
        BOOLEAN = 1

        mode = None
        comboBox = GComboBox()

        @property
        def get_combobox(self):
            return self.comboBox

        def __init__(self):
            pass

        def get_cell_editor_value(self):
            if self.mode == self.ENUM:
                return self.get_combobox_enum()
            elif self.mode == self.BOOLEAN:
                # todo: implement boolean editor
                raise NotImplementedError("Boolean Editor not implemented")
            else:
                raise ValueError("Invalid mode")

    class SettingsRowObject:
        def __init__(self, definition):
            pass

        @property
        def name(self):
            return self.definition.getName()

        def get_settings_choices(self):
            if isinstance(definition, EnumSettingsDefinition):
                # todo: implement enum editor
                raise NotImplementedError("Enum Editor not implemented")
            elif isinstance(definition, BooleanSettingsDefinition):
                # todo: implement boolean editor
                raise NotImplementedError("Boolean Editor not implemented")

    class SettingsEditor(AbstractCellEditor, TableCellEditor):
        ENUM = 0
        BOOLEAN = 1

        mode = None
        comboBox = GComboBox()

        @property
        def get_combobox(self):
            return self.comboBox

        def __init__(self):
            pass

        def get_cell_editor_value(self):
            if self.mode == self.ENUM:
                return self.get_combobox_enum()
            elif self.mode == self.BOOLEAN:
                # todo: implement boolean editor
                raise NotImplementedError("Boolean Editor not implemented")
            else:
                raise ValueError("Invalid mode")

    class SettingsTableModel(AbstractSortedTableModel[SettingsRowObject]):
        rows = []

        @property
        def model_data(self):
            return self.rows

        def __init__(self, settings_defs):
            for sd in settings_defs:
                self.rows.append(SettingsRowObject(sd))

    # todo: implement apply_common_settings and set_choice methods