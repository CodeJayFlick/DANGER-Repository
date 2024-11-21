class GhidraScriptTableModel:
    SCRIPT_ACTION_COLUMN_NAME = "In Tool"
    SCRIPT_STATUS_COLUMN_NAME = "Status"

    EMPTY_STRING = ""
    ERROR_IMG = Icons.ERROR_ICON

    def __init__(self, provider: 'GhidraScriptComponentProvider', info_manager: 'GhidraScriptInfoManager'):
        super().__init__()
        self.provider = provider
        self.info_manager = info_manager

    @property
    def script_list(self):
        return self._script_list

    @script_list.setter
    def script_list(self, value):
        self._script_list = value

    def create_table_column_descriptor(self) -> 'TableColumnDescriptor[ResourceFile]':
        descriptor = TableColumnDescriptor()
        descriptor.add_visible_column(ScriptActionColumn())
        descriptor.add_visible_column(StatusColumn())
        descriptor.add_visible_column(NameColumn(), 1, True)
        descriptor.add_visible_column(DescriptionColumn())
        descriptor.add_visible_column(KeyBindingColumn())
        descriptor.add_hidden_column(PathColumn())
        descriptor.add_visible_column(CategoryColumn())
        descriptor.add_hidden_column(CreatedColumn())
        descriptor.add_visible_column(ModifiedColumn())

        return descriptor

    def get_name(self) -> str:
        return "Scripts"

    def contains(self, row: int):
        return 0 <= row < len(self.script_list)

    def get_script_index(self, script: 'ResourceFile') -> int:
        return self.script_list.index(script)

    @property
    def scripts(self):
        return list(self.script_list)

    def get_script_at(self, row: int) -> 'ResourceFile':
        if 0 <= row < len(self.script_list):
            return self.script_list[row]
        else:
            return None

    def insert_script(self, script: 'ResourceFile'):
        if not self.script_list.contains(script):
            self.script_list.append(script)
            self.fire_table_rows_inserted(len(self.script_list) - 1)

    def insert_scripts(self, scripts: list['ResourceFile']):
        row_start = len(self.script_list)
        for script in scripts:
            if not self.script_list.contains(script):
                self.script_list.append(script)
        self.fire_table_rows_inserted(row_start, row_start + len(scripts) - 1)

    def remove_script(self, script: 'ResourceFile'):
        try:
            index = self.script_list.index(script)
            del self.script_list[index]
            self.fire_table_rows_deleted(index, index)
        except ValueError:
            pass

    def switch_script(self, old_script: 'ResourceFile', new_script: 'ResourceFile'):
        if not (old_script is None or new_script is None):
            try:
                index = self.script_list.index(old_script)
                self.script_list[index] = new_script
                self.fire_table_rows_updated(index, index)
            except ValueError:
                pass

    def get_name_column_index(self) -> int:
        return [col for col in self.get_columns() if isinstance(col, NameColumn)][0].get_column_index()

    @property
    def model_data(self):
        return list(self.script_list)

    @property
    def data_source(self):
        return None

    class ScriptActionColumn(AbstractDynamicTableColumn['ResourceFile', bool, object]):
        pass

    class StatusColumn(AbstractDynamicTableColumn['ResourceFile', 'ImageIcon', object]):
        renderer = DateRenderer()

    class NameColumn(AbstractDynamicTableColumn['ResourceFile', str, object]):
        pass

    class DescriptionColumn(AbstractDynamicTableColumn['ResourceFile', str, object]):
        pass

    class KeyBindingColumn(AbstractDynamicTableColumn['ResourceFile', 'KeyBindingsInfo', object]):
        pass

    class PathColumn(AbstractDynamicTableColumn['ResourceFile', str, object]):
        pass

    class CategoryColumn(AbstractDynamicTableColumn['ResourceFile', str, object]):
        pass

    class CreatedColumn(AbstractDynamicTableColumn['ResourceFile', date, object]):
        renderer = DateRenderer()

    class ModifiedColumn(AbstractDynamicTableColumn['ResourceFile', date, object]):
        renderer = DateRenderer()
