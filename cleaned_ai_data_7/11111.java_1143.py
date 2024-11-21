import re

class FVTableModel:
    DATE_COL = 0
    TIME_COL = 1
    LEVEL_COL = 2
    MESSAGE_COL = 3

    date_regex = re.compile(r'\d{4}-\d{2}-\d{2}')
    space_regex = r'\s+'
    time_regex = re.compile(r'(?:[01]\d|2[0123]):(?:[012345]\d):(?:[012345]\d(,\d\d\d)?)')
    level_regex = re.compile(f'{space_regex}{re.escape(Level.OFF.value)}{space_regex}|' \
                              f'{space_regex}{re.escape(Level.DEBUG.name())}{space_regex}|' \
                              f'{space_regex}{re.escape(Level.TRACE.name())}{space_regex}|' \
                              f'{space_regex}{re.escape(Level.WARN.name())}{space_regex}|' \
                              f'{space_regex}{re.escape(Level.INFO.name())}{space_regex}|' \
                              f'{space_regex}{re.escape(Level.ERROR.name())}{space_regex}|' \
                              f'{space_regex}{re.escape(Level.FATAL.name())}{space_regex}')

    def __init__(self):
        self.dates = []
        self.times = []
        self.levels = []
        self.messages = []

    @property
    def row_count(self):
        return len(self.messages)

    @property
    def column_count(self):
        return 4

    def get_column_name(self, column_index):
        if column_index == FVTableModel.DATE_COL:
            return 'Date'
        elif column_index == FVTableModel.TIME_COL:
            return 'Time'
        elif column_index == FVTableModel.LEVEL_COL:
            return 'Level'
        elif column_index == FVTableModel.MESSAGE_COL:
            return 'Message'

    def get_column_class(self, column_index):
        return str

    def get_value_at(self, row_index, column_index):
        if 0 <= row_index < len(self.messages):
            if column_index == FVTableModel.DATE_COL:
                return self.dates[row_index]
            elif column_index == FVTableModel.TIME_COL:
                return self.times[row_index]
            elif column_index == FVTableView.LEVEL_COL:
                return self.levels[row_index]
            elif column_index == FVTableView.MESSAGE_COL:
                return self.messages[row_index]

    def add_row(self, row, notify=True):
        date = self.get_date(row)
        self.dates.append(date)
        row = row.replace(date, '')
        time = self.get_time(row)
        self.times.append(time)
        row = row.replace(time, '')
        level = self.get_level(row)
        self.levels.append(level)
        row = row.replace(level, '')
        message = row.strip()
        self.messages.append(message)

        if notify:
            # fireTableRowsInserted(self.row_count - 1, self.row_count - 1)
            pass

    def add_rows_to_top(self, rows):
        for i in range(len(rows)):
            self.add_row(rows[i], False)
        # fireTableDataChanged()
        pass

    def add_rows_to_bottom(self, rows):
        for row in rows:
            self.add_row(row, False)
        # fireTableDataChanged()
        pass

    def remove_rows_from_bottom(self, count):
        while len(self.messages) > 0 and count > 0:
            del self.dates[-1]
            del self.levels[-1]
            del self.times[-1]
            del self.messages[-1]
            count -= 1
        # fireTableDataChanged()
        pass

    def remove_rows_from_top(self, count):
        while len(self.messages) > 0 and count > 0:
            if self.dates:
                del self.dates[0]
                del self.levels[0]
                del self.times[0]
                del self.messages[0]
            else:
                break
            count -= 1
        # fireTableDataChanged()
        pass

    def clear(self):
        self.dates.clear()
        self.levels.clear()
        self.messages.clear()
        self.times.clear()
        # fireTableDataChanged()
        pass

    def get_date(self, row):
        return re.search(FVTableModel.date_regex, row).group() if FVTableView.date_regex.search(row) else ''

    def get_level(self, row):
        return re.search(FVTableView.level_regex, row).group().strip() if FVTableView.level_regex.search(row) else ''
