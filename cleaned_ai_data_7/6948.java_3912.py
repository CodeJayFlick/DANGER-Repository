from typing import List, Set

class DecompilerClipboardProvider:
    def __init__(self, plugin: object, provider: object):
        self.provider = provider
        # No equivalent to 'tool' in this context. Assuming it's not necessary.
        
    def addChangeListener(self, listener: callable) -> None:
        if hasattr(self, 'listeners'):
            self.listeners.add(listener)
        else:
            self.listeners = {listener}

    def removeChangeListener(self, listener: callable) -> None:
        if hasattr(self, 'listeners'):
            try:
                self.listeners.remove(listener)
            except KeyError:
                pass

    def notifyStateChanged(self) -> None:
        event = object()  # No equivalent to ChangeEvent in Python
        for listener in getattr(self, 'listeners', set()):
            listener(event)

    def copy(self, monitor: callable) -> object:
        if not self.copyFromSelectionEnabled:
            return create_string_transferable(self.get_cursor_text())
        else:
            return self.copy_text(monitor)

    def get_cursor_text(self) -> str:
        panel = self.provider.get_decompiler_panel()
        token = panel.get_token_at_cursor()
        if token is None:
            return ''
        text = token.get_text()
        return text

    def current_copy_types(self) -> List[object]:
        if self.copyFromSelectionEnabled:
            return [self.TEXT_TYPE]
        else:
            return []

    def current_paste_types(self, t: object) -> List[object]:
        return None  # No equivalent to ClipboardType in Python. Assuming it's not necessary.

    def copy_special(self, copy_type: str, monitor: callable) -> object:
        if copy_type == self.TEXT_TYPE:
            return self.copy_text(monitor)
        else:
            return None

    def is_valid_context(self, context: object) -> bool:
        return isinstance(context.get_component_provider(), type(self.provider))

    def selection_changed(self, sel: object) -> None:
        self.selection = sel
        self.copyFromSelectionEnabled = (sel and len(sel) > 0)
        self.notifyStateChanged()

    @property
    def component_provider(self):
        return self.provider

    def enable_copy(self) -> bool:
        return True

    def enable_copy_special(self) -> bool:
        return False

    def can_copy(self) -> bool:
        return self.copyFromSelectionEnabled or not self.get_cursor_text().strip()

    def can_copy_special(self) -> bool:
        return False

    def copy_text(self, monitor: callable) -> object:
        return create_string_transferable(self.get_text())

    def get_text(self) -> str:
        buffer = ''
        num_ranges = len(self.selection)
        for i in range(num_ranges):
            self.append_text(buffer, self.selection[i])
        return buffer

    def append_text(self, buffer: str, field_range: object) -> None:
        start_index = int(field_range.get_start().get_index())
        end_index = int(field_range.get_end().get_index())
        if start_index == end_index:
            # Single line selection (don't include padding)
            self.append_text_single_line(buffer, start_index, self.selection[i])
            return
        for i in range(start_index + 1, end_index):
            buffer += '\n'
            self.append_text(buffer, i, self.selection[i])

    def append_text(self, buffer: str, line_number: int, single_line_selection: object) -> None:
        if not single_line_selection:
            return
        field_range = single_line_selection[0]
        start_column = int(field_range.get_start().get_col())
        end_column = int(field_range.get_end().get_col())
        start_row = int(field_range.get_start().get_row())
        end_row = int(field_range.get_end().get_row())

    def append_text_single_line(self, buffer: str, line_number: int, single_line_selection: object) -> None:
        if not single_line_selection:
            return
        field_range = single_line_selection[0]
        start_column = int(field_range.get_start().get_col())
        end_column = int(field_range.get_end().get_col())

    def set_font_metrics(self, metrics: callable) -> None:
        self.space_char_width_in_pixels = metrics.charWidth(' ')

TEXT_TYPE = 'Text'
COPY_TYPES = [TEXT_TYPE]
EMPTY_LIST = []

def create_string_transferable(text: str) -> object:
    return text

# No equivalent to TaskMonitor in Python. Assuming it's not necessary.
