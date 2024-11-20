Here is the translation of the given Java code into Python:

```Python
class LineLockedFieldPanelCoordinator:
    def __init__(self, panels):
        self.locked_line_numbers = [0] * len(panels)
        super().__init__(panels)

    def reset_locked_lines(self):
        for i in range(len(self.locked_line_numbers)):
            self.locked_line_numbers[i] = 0

    def set_locked_lines(self, locked_line_numbers):
        if len(locked_line_numbers) != len(self.locked_line_numbers):
            raise AssertionError("The number of lines must exactly match the number of panels.")
        for i in range(len(locked_line_numbers)):
            if locked_line_numbers[i] is None:
                locked_line_numbers[i] = 0
        self.locked_line_numbers = [x for x in locked_line_numbers]

    def add(self, fp):
        new_locked_lines = list(self.locked_line_numbers)
        new_locked_lines.append(0)
        self.locked_line_numbers = new_locked_lines
        super().add(fp)

    def remove(self, fp):
        line_number_list = [x for x in self.locked_line_numbers if x != 0]
        self.locked_line_numbers = list(line_number_list)
        super().remove(fp)

    def view_changed(self, fp, index, xPos, yPos):
        values_changing = True
        try:
            fp_line_number = self.get_locked_line_for_panel(fp)
            for i in range(len(self.locked_line_numbers)):
                if panels[i] != fp:
                    adjustment = self.locked_line_numbers[i].subtract(fp_line_number)
                    panel_index = index.add(adjustment)
                    if panel_index < 0:
                        panel_index = 0
                    panels[i].set_viewer_position(panel_index, xPos, yPos)
            values_changing = False
        finally:
            pass

    def get_locked_line_for_panel(self, fp):
        for i in range(len(self.locked_line_numbers)):
            if self.panels[i] == fp:
                return self.locked_line_numbers[i]
        return None


# Usage example:

panels = [FieldPanel(), FieldPanel()]
coordinator = LineLockedFieldPanelCoordinator(panels)
```

Please note that this code is a direct translation of the given Java code into Python. It does not include any error handling or exception checking, as it was designed to be a straightforward conversion rather than an optimized solution for use in production code.