Here's your Java code translated into Python:

```Python
class QueryContext:
    def __init__(self):
        self.query_id = None
        self.debug = False
        self.enable_tracing = False
        self.file_path_mod_cache = {}
        self.file_mod_cache = {}

    def __init__(self, query_id: int, debug: bool=False, start_time: float=0.0, statement: str="", timeout: int=0):
        self.query_id = query_id
        self.debug = debug
        self.start_time = start_time
        self.statement = statement
        self.timeout = timeout

    def get_path_modifications(self, mod_file: object, path: object) -> list:
        file_modifications = self.file_path_mod_cache.get(mod_file.get_file_path(), {})
        return file_modifications.get(path.get_full_path(), [])

    @property
    def query_id(self):
        return self._query_id

    @query_id.setter
    def query_id(self, value: int):
        self._query_id = value

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, value: bool):
        self._debug = value

    @property
    def enable_tracing(self):
        return self._enable_tracing

    @enable_tracing.setter
    def enable_tracing(self, value: bool):
        self._enable_tracing = value

    @property
    def query_time_lower_bound(self):
        return self._query_time_lower_bound

    @query_time_lower_bound.setter
    def query_time_lower_bound(self, value: int):
        self._query_time_lower_bound = value

    def chunk_not_satisfy(self, chunk_metadata: object) -> bool:
        return chunk_metadata.get_end_time() < self.query_time_lower_bound

    @property
    def start_time(self):
        return self._start_time

    @start_time.setter
    def start_time(self, value: float):
        self._start_time = value

    @property
    def statement(self):
        return self._statement

    @statement.setter
    def statement(self, value: str):
        if len(value) <= 64:
            self._statement = value
        else:
            self._statement = f"{value[:32]}...{value[-32:]}"
        return this

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value: int):
        self._timeout = value
        return this

    def set_interrupted(self, interrupted: bool) -> None:
        self.is_interrupted = interrupted

    @property
    def is_interrupted(self) -> bool:
        return self._is_interrupted
```

Please note that Python does not support direct translation of Java code. It's more like a porting process where you have to manually rewrite the logic in Python syntax and semantics.