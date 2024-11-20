class QueryDataSet:
    def __init__(self):
        self.paths = []
        self.data_types = []
        self.row_limit = 0
        self.row_offset = 0
        self.already_returned_row_num = 0
        self.fetch_size = 10000
        self.ascending = False

    def init_query_dataset_fields(self, paths, data_types, ascending):
        self.paths = paths
        self.data_types = data_types
        self.ascending = ascending

    def has_next(self) -> bool:
        while self.row_offset > 0:
            if self.has_next_without_constraint():
                row_record = next_without_constraint()
                if (self.without_all_null and row_record.is_all_null()) or \
                   (self.without_any_null and row_record.has_null_field()):
                    continue
                self.row_offset -= 1
        return self.has_next_without_constraint()

    def has_next_without_constraint(self) -> bool:
        # abstract method, to be implemented by subclasses

    def next(self):
        if self.row_limit > 0:
            self.already_returned_row_num += 1
        return next_without_constraint()

    @property
    def paths(self):
        return self._paths

    @paths.setter
    def paths(self, value):
        self._paths = value

    @property
    def data_types(self):
        return self._data_types

    @data_types.setter
    def data_types(self, value):
        self._data_types = value

    @property
    def row_limit(self):
        return self._row_limit

    @row_limit.setter
    def row_limit(self, value):
        self._row_limit = value

    @property
    def row_offset(self):
        return self._row_offset

    @row_offset.setter
    def row_offset(self, value):
        self._row_offset = value

    @property
    def already_returned_row_num(self):
        return self._already_returned_row_num

    @already_returned_row_num.setter
    def already_returned_row_num(self, value):
        self._already_returned_row_num = value

    @property
    def fetch_size(self):
        return self._fetch_size

    @fetch_size.setter
    def fetch_size(self, value):
        self._fetch_size = value

    @property
    def ascending(self):
        return self._ascending

    @ascending.setter
    def ascending(self, value):
        self._ascending = value

    class EndPoint:
        def __init__(self, ip: str, port: int):
            self.ip = ip
            self.port = port

        def get_ip(self) -> str:
            return self.ip

        def set_ip(self, value: str):
            self.ip = value

        def get_port(self) -> int:
            return self.port

        def set_port(self, value: int):
            self.port = value

        def __str__(self) -> str:
            return f"ip:{self.port}"
