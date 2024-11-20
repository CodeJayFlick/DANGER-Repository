from datetime import date, timedelta

class UnixDate:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Unix Date"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return "Converts given Unix timestamp to a date. The Unix timespan represents the number of seconds elapsed since 1 January 1970."

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["unix date of 946684800 #1 January 2000 12:00 AM (UTC Time)"]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "2.5"

    @since.setter
    def since(self, value):
        self._since = value

    def convert(self, n: int) -> date:
        seconds = n * 1000
        dt = timedelta(seconds=seconds)
        result_date = date(1970, 1, 1) + dt
        return result_date

# Register the class for usage in your program.
UnixDate()
