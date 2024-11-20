class ShowContinuousQueriesResult:
    def __init__(self,
                 query_sql: str,
                 continuous_query_name: str,
                 target_path: dict,
                 every_interval: int,
                 for_interval: int):
        self.query_sql = query_sql
        self.continuous_query_name = continuous_query_name
        self.target_path = target_path
        self.every_interval = every_interval
        self.for_interval = for_interval

    @property
    def query_sql(self) -> str:
        return self._query_sql

    @query_sql.setter
    def query_sql(self, value: str):
        self._query_sql = value

    @property
    def continuous_query_name(self) -> str:
        return self._continuous_query_name

    @continuous_query_name.setter
    def continuous_query_name(self, value: str):
        self._continuous_query_name = value

    @property
    def target_path(self) -> dict:
        return self._target_path

    @target_path.setter
    def target_path(self, value: dict):
        self._target_path = value

    @property
    def every_interval(self) -> int:
        return self._every_interval

    @every_interval.setter
    def every_interval(self, value: int):
        self._every_interval = value

    @property
    def for_interval(self) -> int:
        return self._for_interval

    @for_interval.setter
    def for_interval(self, value: int):
        self._for_interval = value
