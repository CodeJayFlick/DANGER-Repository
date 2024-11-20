class RowLayout:
    def __init__(self, fields, row_id):
        self.fields = fields
        self.row_id = row_id
        for field in fields:
            if not hasattr(self, 'height_above'):
                self.height_above = 0
            if not hasattr(self, 'height_below'):
                self.height_below = 0
            if field.is_primary():
                self.is_primary = True
            self.height_above = max(self.height_above, field.getHeightAbove())
            self.height_below = max(self.height_below, field.getHeightBelow())
        for field in fields:
            field.row_height_changed(self.height_above, self.height_below)

    def get_height(self):
        return self.height_above + self.height_below

    def get_compressable_width(self):
        start_x = 0
        row_width = start_x
        for i in range(len(fields) - 1):
            field = fields[i]
            width = field.getWidth()
            row_width += width
        last_field = fields[-1]
        width = last_field.getWidth()
        preferred_width = last_field.getPreferredWidth()
        row_width += min(width, preferred_width)
        return row_width

    def get_height_above(self):
        return self.height_above

    def get_height_below(self):
        return self.height_below

    def get_row_id(self):
        return self.row_id

    def insert_space_above(self, size):
        self.height_above += size

    def insert_space_below(self, size):
        self.height_below += size

    def get_num_fields(self):
        return len(fields)

    def get_field(self, index):
        return fields[index]

    def paint(self, c, g, context, rect, color_manager, cursor_location):
        if (rect.y >= self.height_above + self.height_below) or (rect.y + rect.height < 0):
            return
        g.translate(0, self.height_above)
        rect.y -= self.height_above
        for i in range(len(fields)):
            paint_gap_selection(g, color_manager, rect, i)
            row_col_location = None
            if cursor_location and cursor_location.field_num == i:
                row_col_location = RowColLocation(cursor_location.row, cursor_location.col)
            field_color_manager = color_manager.get_field_background_color_manager(i)
            paint_field_background(g, i, field_color_manager)
            fields[i].paint(c, g, context, rect, field_color_manager, row_col_location, self.height_above + self.height_below)

    def paint_gap_selection(self, g, color_manager, rect, gap_index):
        if gap_index == -1:
            gap_index = len(fields) - 1
        start_x = gap_index == 0 and rect.x or fields[gap_index - 1].get_start_x() + fields[gap_index - 1].width()
        end_x = gap_index >= len(fields) and rect.x + rect.width or fields[gap_index].get_start_x()
        if start_x < end_x:
            g.set_color(color_manager.get_padding_color(gap_index))
            g.fill_rect(start_x, -self.height_above, end_x - start_x, self.height_above + self.height_below)

    def paint_field_background(self, g, field_num, color_manager):
        background_color = color_manager.get_background_color()
        if background_color is not None:
            g.set_color(background_color)
            x1 = fields[field_num].get_start_x()
            y1 = -fields[field_num].getHeightAbove()
            w = fields[field_num].getWidth()
            h = self.height_above + self.height_below
            g.fill_rect(x1, y1, w, h)

    def set_cursor(self, cursor_location, x, y):
        index = self.find_appropriate_field_index(x, y)
        if index < 0:
            return -1
        field = fields[index]
        offset_y = y - self.height_above
        cursor_location.field_num = index
        cursor_location.row = field.get_row(offset_y)
        cursor_location.col = field.get_col(cursor_location.row, x)
        return field.get_x(cursor_location.row, cursor_location.col)

    def get_cursor_rect(self, field_num, row, col):
        if field_num >= len(fields) or not fields[field_num].isValid(row, col):
            return None
        rect = fields[field_num].get_cursor_bounds(row, col)
        rect.y += self.height_above
        return rect

    def cursor_up(self, cursor_location, last_x):
        if cursor_location.row > 0:
            cursor_location.row -= 1
            cursor_location.col = fields[cursor_location.field_num].get_col(cursor_location.row, last_x)
            return True
        else:
            return False

    def cursor_down(self, cursor_location, last_x):
        if cursor_location.row < len(fields[cursor_location.field_num]).getNumRows() - 1:
            cursor_location.row += 1
            cursor_location.col = fields[cursor_location.field_num].get_col(cursor_location.row, last_x)
            return True
        else:
            return False

    def cursor_beginning(self):
        field = fields[0]
        cursor_location = RowColLocation(field.get_row(last_cursor_y), 0)
        cursor_location.field_num = 0
        return field.get_x(cursor_location.row, cursor_location.col)

    def cursor_end(self):
        field = fields[-1]
        cursor_location = RowColLocation(field.get_row(last_cursor_y), len(fields) - 1)
        cursor_location.field_num = len(fields) - 1
        return field.get_x(cursor_location.row, cursor_location.col)

    def enter_layout(self, cursor_location, last_x, from_top):
        if (from_top and y_pos >= self.height_above + self.height_below) or not contains(y_pos):
            return False
        index = self.find_appropriate_field_index(last_x, y_pos - self.height_above)
        if index < 0:
            return False
        cursor_location.field_num = index
        field = fields[index]
        x = last_x
        y = from_top and -field.getHeightAbove() or field.getHeightBelow() - 1
        cursor_location.row = field.get_row(y)
        cursor_location.col = field.get_col(cursor_location.row, x)
        return True

    def get_scrollable_unit_increment(self, top_of_screen, direction):
        max = 0
        if direction > 0:
            if top_of_screen < self.height_above - self.max_height_above:
                return self.height_above - self.max_height_above - top_of_screen
            else:
                max = self.height_above + self.height_below - top_of_screen
        elif direction < 0:
            max = -top_of_screen

        local_top_of_screen = top_of_screen - self.height_above
        for field in fields:
            if field is not None:
                x = field.get_scrollable_unit_increment(local_top_of_screen, direction, max)
                if (direction > 0 and x > 0 and x < max) or (direction < 0 and x < 0 and x > max):
                    return x
        return max

    def contains(self, y_pos):
        if (y_pos >= 0 and y_pos < self.height_above + self.height_below):
            return True
        else:
            return False

class RowColLocation:
    def __init__(self, row, col):
        self.row = row
        self.col = col

def main():
    fields = [Field1(), Field2()]
    layout = RowLayout(fields, 0)
    # usage of the class...

if __name__ == "__main__":
    main()
