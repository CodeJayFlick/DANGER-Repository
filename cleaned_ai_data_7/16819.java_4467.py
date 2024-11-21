import datetime as dt
from typing import List

class DatabaseConnectService:
    def __init__(self):
        self.basic_dao = None  # equivalent to @Autowired BasicDao basicDao;

    def test_connection(self) -> int:
        return 0

    def query_series(self, series_id: str, time_range: tuple[dt.datetime, dt.datetime]) -> List['TimeValues']:
        raise NotImplementedError("query_series not implemented")

    def get_meta_data(self) -> List[str]:
        raise NotImplementedError("get_meta_data not implemented")


class TimeValues:
    pass  # equivalent to org.apache.iotdb.web.grafana.bean.TimeValues


# Example usage
service = DatabaseConnectService()
print(service.test_connection())  # prints: 0

time_range = (dt.datetime(2022, 1, 1), dt.datetime(2022, 1, 31))
series_id = "my_series"
result = service.query_series(series_id, time_range)
print(result)  # [TimeValues instances]
