Here is the equivalent Python code:

```Python
import datetime

class Iso8601Format:
    UTC = datetime.timezone.utc

    def __init__(self, format_string):
        self.format_string = format_string
        self.locale = 'US'
        self.time_zone = Iso8601Format.UTC

    @classmethod
    def new_time_format(cls):
        return cls("HH:mm:ss")

    @classmethod
    def new_date_format(cls):
        return cls("yyyy-MM-dd")

    @classmethod
    def new_datetime_format(cls):
        return cls("yyyy-MM-dd HH:mm:ss")

    @classmethod
    def format_datetime(cls, date):
        return datetime.datetime.strftime(date, cls.new_datetime_format().format_string)

    @classmethod
    def parse_datetime(cls, source):
        try:
            return datetime.datetime.strptime(source, cls.new_datetime_format().format_string)
        except ValueError as e:
            raise ParseException(str(e))

    @classmethod
    def new_datetime_format_t(cls):
        return cls("yyyy-MM-dd'T'HH:mm:ss'Z'")

    @classmethod
    def format_datetime_t(cls, date):
        return datetime.datetime.strftime(date, cls.new_datetime_format_t().format_string)

    @classmethod
    def parse_datetime_t(cls, source):
        try:
            return datetime.datetime.strptime(source, cls.new_datetime_format_t().format_string)
        except ValueError as e:
            raise ParseException(str(e))

class ParseException(Exception):
    pass

# Example usage:

date = datetime.date.today()
print(Iso8601Format.format_datetime(date))  # Format the date
try:
    print(Iso8601Format.parse_datetime("2022-01-01"))  # Parse a date string
except ParseException as e:
    print(str(e))
```

Please note that Python's `datetime` module does not have direct equivalents for Java's `SimpleDateFormat`, `TimeZone`, and `ParseException`. The code above uses the equivalent classes from Python.