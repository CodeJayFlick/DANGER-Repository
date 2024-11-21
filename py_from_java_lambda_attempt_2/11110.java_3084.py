Here is the translation of the Java code into Python:

```Python
class FVTable:
    def __init__(self):
        self.reader = None
        self.viewportUtility = None
        self.model = None
        self.eventListener = None
        self.shiftDown = False
        self.mouseDragging = False

    def setShiftDown(self, is_down):
        self.shiftDown = is_down

    def setMouseDragging(self, is_mouse_dragging):
        self.mouseDragging = is_mouse_dragging

    def addRow(self, row):
        model = (self.model)
        model.add_row(row, True)

    def addRows(self, rows):
        model = (self.model)
        model.add_rows_to_bottom(rows)

    def restoreSelection(self):
        if not self.model.get_num_chunks() > 0:
            return
        first_row_chunk = self.model.get(0)
        last_row_chunk = self.model.get(self.model.get_num_chunks() - 1)
        if first_row_chunk is None or last_row_chunk is None:
            return
        start_byte_pos = first_row_chunk.start
        end_byte_pos = last_row_chunk.end

        # CASE 1: Selection encompasses all of the table.
        if self.model.selected_byte_start <= start_byte_pos and self.model.selected_byte_end >= end_byte_pos:
            set_row_selection_interval(0, get_row_count() - 1)
        elif (self.model.selected_byte_start >= start_byte_pos and
              self.model.selected_byte_start <= last_row_end) and (
                self.model.selected_byte_end > last_row_end):
            row_start = model.get_row_for_byte_pos(self.model.selected_byte_start)
            if check_bounds(row_start, get_row_count() - 1):
                set_row_selection_interval(row_start, get_row_count() - 1)

        # CASE 3: Selection start is in the table and so is the end.
        elif (self.model.selected_byte_start >= start_byte_pos and
              self.model.selected_byte_start <= last_row_end) and (
                self.model.selected_byte_end >= first_row_chunk.start and
                self.model.selected_byte_end <= last_row_chunk.end):
            row_start = model.get_row_for_byte_pos(self.model.selected_byte_start)
            if check_bounds(row_start, get_row_count() - 1):
                set_row_selection_interval(row_start, get_row_count() - 1)

        # CASE 4: Selection start is not in the table but the end is.
        else:
            try:
                lines = self.reader.read_next_chunk()
                if len(lines) == 0:
                    return
                model.add_rows_to_bottom(lines)
                byte_range = model.get_file_position_for_row(get_row_count() - 1)
                if byte_range is None:
                    return
                start_byte_pos = byte_range.start
                end_byte_pos = byte_range.end

            except IOException as e:
                Msg.error(self, "Error reading next chunk of data", e)

    def clear(self):
        model = (self.model)
        model.clear()

    def increment_and_add_selection(self, rows):
        row_selected = get_row()
        if row_selected < 0 and self.model.selected_byte_start >= 0:
            try:
                lines = self.reader.read_next_chunk_from(self.model.selected_byte_start)
                model.add_rows_to_top(lines)

            except IOException as e:
                Msg.error(self, "Error reading next chunk of data starting from byte" + str(
                    self.model.selected_byte_start), e)

        elif row_selected - rows >= 0:
            pair = model.get_file_position_for_row(row_selected - rows)
            if pair is None:
                return
            start_byte_pos = pair.start

    def decrement_and_add_selection(self, rows):
        row_selected = get_row()
        if row_selected < 0 and self.model.selected_byte_start >= 0:
            try:
                lines = self.reader.read_previous_chunk()
                model.add_rows_to_top(lines)

            except IOException as e:
                Msg.error(self, "Error reading previous chunk of data", e)
        elif row_selected - rows >= 0:
            pair_first_row = model.get_file_position_for_row(row_selected - rows)
            if pair_first_row is None:
                return
            start_byte_pos = pair_first_row.start

    def value_changed(self):
        super().value_changed()
        # This check ensures that we only update the selected row when it happens as a result of user input (table selection 
        # happens behind the scenes for other reasons that would be problematic).
        if self.shiftDown and get_selected_rows()[0] >= 0:
            try:
                model.selected_byte_start = start_byte_pos
                restore_selection()

    def create_key_bindings(self, reader, model):
        im_table = getInputMap()
        am_table = getActionMap()
        im_table.put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), "DownArrow")
        am_table.put("DownArrow", new ArrowDownAction(event_listener))
        # Handle arrow up and down when the shift key is pressed
    def mouse_dragged(self):
        self.mouseDragging = True

    def mouse_moved(self):
        pass

    def create_key_bindings(self, reader, model):
        im_table = getInputMap()
        am_table = getActionMap()

    def check_bounds(self, row_start, row_end):
        return (row_start >= 0 and row_end >= 0)

    def set_row_selection_interval(self):

    def mouse_dragged(self):
        self.mouseDragging = True

    def mouse_moved(self):
        pass