class BasicDecompilerFieldPanelCoordinator:
    def __init__(self, dual_decompiler_panel: 'BasicDecompilerCodeComparisonPanel', sync_line_location: bool):
        self.dual_decompiler_panel = dual_decompiler_panel
        self.sync_line_location = sync_line_location

    def left_location_changed(self, left_program_location: 'ProgramLocation'):
        if self.sync_line_location:
            focused_decomposer_panel = self.dual_decompiler_panel.get_focused_decomposer_panel()
            left_panel = self.dual_decompiler_panel.get_left_panel()
            right_panel = self.dual_decompiler_panel.get_right_panel()

            if focused_decomposer_panel != left_panel:
                return

            left_decomposer_panel = left_panel.get_decomposer_panel()
            right_decomposer_panel = right_panel.get_decomposer_panel()

            left_field_location = left_decomposer_panel.get_cursor_position()
            right_decomposer_panel.set_cursor_position(left_field_location)

    def right_location_changed(self, right_program_location: 'ProgramLocation'):
        if self.sync_line_location:
            focused_decomposer_panel = self.dual_decompiler_panel.get_focused_decomposer_panel()
            left_panel = self.dual_decompiler_panel.get_left_panel()
            right_panel = self.dual_decompiler_panel.get_right_panel()

            if focused_decomposer_panel != right_panel:
                return

            left_decomposer_panel = left_panel.get_decomposer_panel()
            right_decomposer_panel = right_panel.get_decomposer_panel()

            right_field_location = right_decomposer_panel.get_cursor_position()
            left_decomposer_panel.set_cursor_position(right_field_location)
