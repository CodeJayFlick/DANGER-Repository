Here is the translation of the given Java code into Python:

```Python
import logging
from typing import List

class BasicDaoImpl:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.timestamp_radio_x = -1
        self.is_down_sampling = False
        self.continuous_data_function = ""
        self.discrete_data_function = ""
        self.interval = ""

    @property
    def timestamp_precision(self) -> str:
        return "ms"

    @timestamp_precision.setter
    def timestamp_precision(self, value: str):
        if value in ["us", "ns"]:
            if value == "us":
                self.timestamp_radio_x = 1000
            elif value == "ns":
                self.timestamp_radio_x = 1000000
        else:
            self.timestamp_radio_x = 1

    @property
    def is_down_sampling(self) -> bool:
        return False

    @is_down_sampling.setter
    def is_down_sampling(self, value: str):
        if value.lower() == "true":
            self.is_down_sampling = True
        else:
            self.is_down_sampling = False

    @property
    def continuous_data_function(self) -> str:
        return ""

    @continuous_data_function.setter
    def continuous_data_function(self, value: str):
        self.continuous_data_function = value

    @property
    def discrete_data_function(self) -> str:
        return ""

    @discrete_data_function.setter
    def discrete_data_function(self, value: str):
        self.discrete_data_function = value

    @property
    def interval(self) -> str:
        return ""

    @interval.setter
    def interval(self, value: str):
        self.interval = value

    def get_meta_data(self) -> List[str]:
        conn = None
        try:
            conn = psycopg2.connect(
                host="localhost",
                database="mydatabase",
                user="username",
                password="password"
            )
            cur = conn.cursor()
            cur.execute("show timeseries root.*")
            result = cur.fetchall()
            self.logger.info("Start to get timeseries")
            columns_name = []
            for row in result:
                time_series = row[0]
                column_name = time_series.split('.')[-1]
                columns_name.append(column_name)
        except (Exception, psycopg2.DatabaseError) as error:
            print(error)
        finally:
            if conn is not None:
                conn.close()

    def query_series(self, s: str, time_range: Pair[ZonedDateTime, ZonedDateTime]) -> List[TimeValues]:
        try:
            return self.query_series_internal(s, time_range, self.continuous_data_function)
        except Exception as e:
            # Try it with discreteDataFunction
            try:
                return self.query_series_internal(s, time_range, self.discrete_data_function)
            except Exception as e2:
                self.logger.warn("Even {} query did not succeed, returning NULL now".format(self.discrete_data_function), e2)
                return []

    def query_series_internal(
        self,
        s: str,
        time_range: Pair[ZonedDateTime, ZonedDateTime],
        function: str
    ) -> List[TimeValues]:
        from_time = zoned_covert_to_long(time_range.left)
        to_time = zoned_covert_to_long(time_range.right)

        sql = f"SELECT {s.split('.')[-1]} FROM root.{s} WHERE time > {from_time} and time < {to_time}"
        column_name = "root." + s

        hours = duration_between(time_range.left, time_range.right).total_seconds() / 3600
        interval_local = self.get_interval(hours)
        if interval_local:
            sql = f"SELECT {function}({s.split('.')[-1]}) FROM root.{s} WHERE time > {from_time} and time < {to_time} group by ([{from_time}, {to_time}),{interval_local}"
            column_name = function + "(root." + s + ")"

        self.logger.info(sql)
        return execute_sql_query(sql)

    def get_interval(self, hours: float) -> str:
        if not self.is_down_sampling or hours > 1:
            return ""

        if hours < 30 * 24 and hours > 24:
            return "1h"
        elif hours > 30 * 24:
            return "1d"

        return self.interval

    def zoned_covert_to_long(self, time: ZonedDateTime) -> int:
        return time.toInstant().toEpochMilli()

class TimeValuesRowMapper:
    def __init__(self):
        pass

    @staticmethod
    def map_row(resultSet: ResultSet, i: int) -> TimeValues:
        tv = TimeValues()
        tv.time = resultSet.getLong("Time") / timestamp_radio_x
        value_string = resultSet.getString(column_name)
        if value_string is not None:
            try:
                tv.value = float(value_string)
            except Exception as e:
                tv.value = value_string

        return tv