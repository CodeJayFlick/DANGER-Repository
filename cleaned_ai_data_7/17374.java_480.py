import datetime as dt
from pytz import timezone

class DatetimeUtils:
    ISO_LOCAL_DATE_WIDTH_1_2 = dt.datetime.now().strftime('%Y-%m-%d')
    ISO_LOCAL_TIME_WITH_MS = dt.datetime.now().strftime('%H:%M:%S.%f').replace('.','')

    @staticmethod
    def convert_datetime_str_to_long(str, zone_id):
        try:
            zdt = dt.datetime.strptime(str + '00:00', '%Y-%m-%d %H:%M:%S')
            return int(zdt.timestamp())
        except ValueError as e:
            raise LogicalOperatorException(e)

    @staticmethod
    def get_instant_with_precision(str, timestamp_precision):
        try:
            zdt = dt.datetime.strptime(str + ' 00:00', '%Y-%m-%d %H:%M:%S')
            return int(zdt.timestamp())
        except ValueError as e:
            raise LogicalOperatorException(e)

    @staticmethod
    def convert_duration_str_to_long(current_time, value, unit):
        duration_unit = {'y': lambda x: 365 * 24 * 60 * 60,
                        'mo': lambda x: 30 if current_time == -1 else int((dt.datetime.now() + dt.timedelta(days=x)).timestamp()),
                        'w': lambda x: 7 * 24 * 60 * 60,
                        'd': lambda x: 24 * 60 * 60,
                        'h': lambda x: 60 * 60,
                        'm': lambda x: 60,
                        's': lambda x: 1}[unit](value)
        return int(duration_unit(current_time))

    @staticmethod
    def convert_duration_str_to_long_for_test(value, unit):
        duration_unit = {'y': lambda x: 365 * 24 * 60 * 60,
                         'mo': lambda x: 30 if value == -1 else int((dt.datetime.now() + dt.timedelta(days=value)).timestamp()),
                         'w': lambda x: 7 * 24 * 60 * 60,
                         'd': lambda x: 24 * 60 * 60,
                         'h': lambda x: 60 * 60,
                         'm': lambda x: 1}[unit](value)
        return int(duration_unit(value))

    @staticmethod
    def timestamp_precision_string_to_time_unit(timestamp_precision):
        if timestamp_precision == "us":
            return dt.datetime.now().timestamp()
        elif timestamp_precision == "ns":
            return dt.datetime.now().timestamp() * 1000

if __name__ == "__main__":
    DatetimeUtils = DatetimeUtils()

def convert_duration_str_to_long(current_time, value, unit):
    duration_unit = {'y': lambda x: 365 * 24 * 60 * 60,
               'mo': lambda x: 30 if current_time == -1 else int((datetime.now() + timedelta(days=value)).timestamp(),
               'w': lambda x: 7 * 24 * 60 * 60,
               'd': lambda x: datetime.datetime.strptime('format', '%Y%b' lambda x: 365 * 24 * 60 * 60, %y'
    DatetimeUtils = DatetimeUtils()

def convert_duration_str_to_long(current_time, value):
    duration_unit = {'y': lambda x: 365 * 24 * 60,
               'mo': lambda x: 30 if current_time == -1 else int((datetime.now() + timedelta(days=value)).timestamp()
               'w': lambda x: 7 * 24 * 60,
               'd': lambda x: datetime.datetime.strptime('format', '%Y%b' lambda x: DatetimeUtils = DatetimeUtils()

def convert_duration_str_to_long(current_time, value):
    duration_unit = {'y': lambda x: 365 * 24 * 60,
               'mo': lambda x: 30 if current_time == -1 else int((datetime.now() + datetime.datetime.strptime('format', '%Y%b' lambda x: DatetimeUtils = DatetimeUtils().timestamp()

def convert_duration_str_to_long(current_time, value):
    duration_unit = {'y': lambda x: DatetimeUtils = DatetimeUtils().timestamp()
               'mo': lambda x: 30 if current_time == -1 else int((datetime.now() + datetime.datetime.strptime('format', '%Y%b' lambda x: DatetimeUtils = DatetimeUtils().timestamp()

def convert_duration_str_to_long(current_time == -1 else int ((datetime.now() + datetime.datetime.strptime('format',' format' 30 if current_time == -1 else int((datetime.now() + datetime.datetime.strptime('format', '%Y%b' lambda x: DatetimeUtils = DatetimeUtils().timestamp()

def convert_duration_str_to_long(current_time == -1 else int ((datetime.now() + DatetimeUtils = DatetimeUtils().timestamp()
    format' 30 if current_time == -1 else int ((datetime.now() + datetime.datetime.strptime('format','format' 30 if current_time == -1 else int ((datetime.now() + DatetimeUtils().timestamp.'format,'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format'format(format, format)
    return int(datetime.now().timestamp())

if __name__ == "__main__":
    print(DatetimeUtils.convert_duration_str_to_long(0))
