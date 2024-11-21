class AnalysisEnablementTableModel:
    def __init__(self, panel: 'AnalysisPanel', analyzer_states):
        self.panel = panel
        self.analyzer_states = analyzer_states
        # Set default table sort state (not implemented in this example)
        pass

    def set_data(self, analyzer_states):
        self.analyzer_states = analyzer_states
        self.fire_table_data_changed()

    @property
    def name(self) -> str:
        return "Analysis Enablement"

    @property
    def model_data(self) -> list['AnalyzerEnablementState']:
        return self.analyzer_states

    def create_table_column_descriptor(self):
        descriptor = TableColumnDescriptor()
        descriptor.add_visible_column(AnalyzerEnabledColumn())
        descriptor.add_visible_column(AnalyzerNameColumn())
        return descriptor

    def get_data_source(self):
        return None

    def is_cell_editable(self, row_index: int, column_index: int) -> bool:
        return column_index == 0

    def set_value_at(self, value: object, row_index: int, column_index: int):
        if column_index == AnalysisPanel.COLUMN_ANALYZER_IS_ENABLED:
            enabled = (value is not None and isinstance(value, bool))
            state = self.analyzer_states[row_index]
            state.set_enabled(enabled)
            analyzer_name = state.get_name()
            self.panel.set_analyzer_enabled(analyzer_name, enabled, True)
            self.fire_table_rows_updated(row_index, row_index)

    def is_sortable(self, column_index: int) -> bool:
        return False

class EnabledColumn(AbstractDynamicTableColumn[bool]):
    @property
    def name(self):
        return "Enabled"

    def get_value(self, state: 'AnalyzerEnablementState', settings: object, data: object, provider: object) -> bool:
        return state.is_enabled()

    def get_column_renderer(self) -> GColumnRenderer[bool]:
        return EnabledColumnTableCellRenderer()

class AnalyzerNameColumn(AbstractDynamicTableColumn[str]):
    @property
    def name(self):
        return "Analyzer"

    def get_value(self, state: 'AnalyzerEnablementState', settings: object, data: object, provider: object) -> str:
        value = state.get_name()
        if state.is_prototype():
            value += f" ({AnalysisPanel.PROTOTYPE})"
        return value

    def get_column_renderer(self) -> GColumnRenderer[str]:
        return AnalyzerNameTableCellRenderer()

class EnabledColumnTableCellRenderer(GBooleanCellRenderer):
    @property
    def name(self):
        return "Enabled"

    def set_tooltip(self, component: object, text: str):
        if isinstance(component, JComponent):
            ((JComponent)component).set_tool_tip_text(text)

    def get_table_cell_renderer_component(self, table: 'JTable', value: bool, selected: bool, has_focus: bool, row_index: int, column_index: int) -> object:
        component = super().get_table_cell_renderer_component(table, value, selected, has_focus, row_index, column_index)
        state = self.get_row_object(row_index)

        if not state.is_default_enablement():
            if selected:
                component.set_background_color(BG_COLOR_NOT_DEFAULT_ENABLEMENT_SELECTED)
            else:
                component.set_background_color(BG_COLOR_NOT_DEFAULT_ENABLEMENT)

        self.set_tooltip(component, "This option differs from the default")
        return component

class AnalyzerNameTableCellRenderer(AbstractGColumnRenderer[str]):
    @property
    def name(self):
        return "Analyzer"

    def set_tooltip(self, component: object, text: str):
        if isinstance(component, JComponent):
            ((JComponent)component).set_tool_tip_text(text)

    def get_table_cell_renderer_component(self, data: 'GTableCellRenderingData') -> object:
        component = super().get_table_cell_renderer_component(data)
        value = data.get_value()

        if value is None:
            return component

        analyzer_name = str(value)

        if analyzer_name.endswith(AnalysisPanel.PROTOTYPE):
            component.set_foreground_color(ColorUtils.derive_foreground(component.get_background_color(), ColorUtils.HUE_RED))

        state = self.get_row_object(data.get_row_index())

        if not state.is_default_enablement():
            if data.is_selected():
                component.set_background_color(BG_COLOR_NOT_DEFAULT_ENABLEMENT_SELECTED)
                component.set_foreground_color(Color.BLACK)
            else:
                component.set_background_color(BG_COLOR_NOT_DEFAULT_ENABLEMENT)

        self.set_tooltip(component, "This option differs from the default")
        return component
