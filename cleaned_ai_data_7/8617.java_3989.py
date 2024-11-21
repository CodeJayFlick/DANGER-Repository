class SymbolServerTableModel:
    def __init__(self):
        self.rows = []
        self.data_changed = False

    def is_empty(self):
        return len(self.rows) == 0

    def set_symbol_servers(self, symbol_servers):
        self.rows.clear()
        for symbol_server in symbol_servers:
            row = SymbolServerRow(symbol_server)
            self.rows.append(row)
        self.fire_table_data_changed()

    def get_symbol_servers(self):
        return [row.get_symbol_server() for row in self.rows]

    def add_symbol_server(self, ss):
        row = SymbolServerRow(ss)
        self.rows.append(row)
        self.data_changed = True
        self.fire_table_data_changed()

    def add_symbol_servers(self, symbol_servers):
        for symbol_server in symbol_servers:
            row = SymbolServerRow(symbol_server)
            self.rows.append(row)
        self.data_changed = True
        self.fire_table_data_changed()

    def delete_rows(self, rowIndexes):
        for i in range(len(roiwIndexes) - 1, -1, -1):
            del self.rows[rowIndex[0]]
        self.data_changed = True
        self.fire_table_data_changed()

    def refresh_symbol_server_location_status(self):
        rows_copy = list(self.rows)
        TaskLauncher.launch_non_modal("Refresh Symbol Server Location Status", monitor ->
            for row in rows_copy:
                if monitor.is_cancelled():
                    break
                monitor.set_message(f"Checking {row.get_symbol_server().name}")
                row.set_status(row.get_symbol_server().is_valid(monitor) and VALID or INVALID)
        finally:
            Swing.run_later(self.fire_table_data_changed)

    def move_row(self, rowIndex, delta_index):
        dest_index = rowIndex + delta_index
        if 0 <= rowIndex < len(self.rows) and 0 <= dest_index < len(self.rows):
            symbol_server_row1 = self.rows[rowIndex]
            symbol_server_row2 = self.rows[dest_index]
            self.rows[dest_index] = symbol_server_row1
            self.rows[rowIndex] = symbol_server_row2

        self.data_changed = True
        self.fire_table_data_changed()

    def is_data_changed(self):
        return self.data_changed

    def set_data_changed(self, b):
        self.data_changed = b

    @property
    def name(self):
        return "Symbol Server Locations"

    @property
    def model_data(self):
        return self.rows

    @property
    def data_source(self):
        return self.rows

    def is_sortable(self, column_index):
        return False

    def set_value_at(self, value, row_index, column_index):
        if isinstance(column_index, int) and 0 <= row_index < len(self.rows) and 0 <= column_index < len(self.rows[0]):
            self.rows[rowIndex][column_index] = value
            self.data_changed = True
            self.fire_table_data_changed()

    def is_cell_editable(self, row_index, column_index):
        return False

class StatusColumn:
    VALID_ICON = Icons.get("images/checkmark_green.gif")
    INVALID_ICON = Icons.ERROR_ICON
    icons = [None, VALID_ICON, INVALID_ICON]
    toolTips = ["Status: Ok", "Status: Failed"]

    def get_value(self, row_object, settings, service_provider):
        return row_object.status

class EnabledColumn:
    pass

class LocationColumn:
    pass

class EnumIconColumnRenderer(E extends Enum<E>):
    icons
    toolTips

    def __init__(self, enum_class, icons, toolTips):
        if len(enum_class.getEnumConstants()) != len(icons) or len(icons) != len(toolTips):
            raise ValueError()
        self.icons = icons
        self.toolTips = toolTips

    def get_table_cell_renderer_component(self, data):
        renderer = super().get_table_cell_renderer_component(data)
        e = data.value
        if e is not None:
            renderer.setIcon(self.icons[e.ordinal()])
            renderer.setToolTipText(self.toolTips[e.ordinal()])
        return renderer

class SymbolServerRow:
    def __init__(self, symbol_server):
        self.symbol_server = symbol_server
        self.status = VALID
