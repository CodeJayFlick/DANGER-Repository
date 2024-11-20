import datetime as dt
from dateutil.parser import parse

class CreationDateProjectDataColumn:
    def __init__(self):
        self.format = dt.datetime.strptime("EEE MMM dd HH:mm:ss Z YYYY", "%a %b %d %H:%M:%S %Z %Y")

    def get_column_name(self):
        return "Created"

    def get_value(self, info, settings, data, services=None) -> dt.date:
        date_string = info.get_meta_data_value("Date Created")
        if date_string is not None:
            try:
                return parse(date_string)
            except ValueError:  # or whatever exception you want to catch
                pass
        return dt.datetime.min

    def get_column_preferred_width(self):
        return 200

    def is_default_column(self) -> bool:
        return False

    def get_priority(self) -> int:
        return 7


# Example usage:

column = CreationDateProjectDataColumn()
print(column.get_column_name())  # prints: Created
date_value = column.get_value(None, None, None)
if date_value is not dt.datetime.min:
    print(date_value.strftime("%Y-%m-%d %H:%M:%S"))  # prints the parsed date in a human-readable format

