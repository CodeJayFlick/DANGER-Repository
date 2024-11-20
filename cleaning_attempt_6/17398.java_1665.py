import logging
from datetime import zoneinfo
from typing import Dict, Set

class SessionManager:
    _logger = logging.getLogger(__name__)

    def __init__(self):
        self._curr_session_id: ThreadLocal[int] = threading.local()
        self._session_id_to_username: Dict[int, str] = {}
        self._session_id_to_zone_id: Dict[int, zoneinfo.ZoneInfo] = {}
        self._session_id_generator: int = 0
        self._statement_id_generator: int = 0

    def get_curr_session_id(self) -> int:
        return self._curr_session_id.get()

    def remove_curr_session_id(self):
        self._curr_session_id.remove()

    def request_session_id(self, username: str, zone_id: str) -> int:
        session_id = self._session_id_generator + 1
        self._curr_session_id.set(session_id)
        self._session_id_to_username[session_id] = username
        self._session_id_to_zone_id[session_id] = zoneinfo.ZoneInfo(zone_id)

    def release_session_resource(self, session_id: int) -> bool:
        if session_id not in self._session_id_to_zone_id:
            return False

        del self._session_id_to_username[session_id]
        del self._session_id_to_zone_id[session_id]

        for statement_id_set in self._get_statement_ids(session_id):
            for query_id_set in self.get_query_ids(statement_id_set):
                for query_id in query_id_set:
                    release_query_resource(query_id)

    def get_session_id_by_query_id(self, query_id: int) -> int:
        for session_to_statements in self._session_id_to_statement_id.items():
            if query_id in session_to_statements[1]:
                return session_to_statements[0]

    def request_statement_id(self, session_id: int) -> int:
        statement_id = self._statement_id_generator + 1
        self._get_statement_ids(session_id).add(statement_id)
        return statement_id

    def close_statement(self, session_id: int, statement_id: int):
        for query_id_set in self.get_query_ids([statement_id]):
            for query_id in query_id_set:
                release_query_resource(query_id)

        if session_id in self._session_id_to_statement_id:
            self._get_statement_ids(session_id).remove(statement_id)

    def request_query_id(self, is_data_query: bool) -> int:
        return QueryResourceManager().assign_query_id(is_data_query)

    def release_query_resource(self, query_id: int):
        if query_id not in self._query_id_to_dataset:
            return

        dataset = self._query_id_to_dataset[query_id]
        del self._query_id_to_dataset[query_id]

        if isinstance(dataset, UDTFDataSet):
            dataset.finalize_udfs(query_id)

    def release_query_resource_no_exceptions(self, query_id: int):
        try:
            self.release_query_resource(query_id)
        except Exception as e:
            self._logger.warn("Error occurred while releasing query resource:", e)

    @property
    def username(self) -> str:
        return self._session_id_to_username.get()

    @property
    def zone_id(self) -> zoneinfo.ZoneInfo:
        return self._session_id_to_zone_id

    def set_timezone(self, session_id: int, zone: str):
        if session_id not in self._session_id_to_zone_id:
            return

        self._session_id_to_zone_id[session_id] = zoneinfo.ZoneInfo(zone)

    @property
    def has_dataset(self) -> bool:
        return query_id in self._query_id_to_dataset

    @property
    def dataset(self) -> QueryDataSet:
        return self._query_id_to_dataset.get()

    @dataset.setter
    def set_dataset(self, query_id: int, dataset: QueryDataSet):
        if query_id not in self._query_id_to_dataset:
            self._query_id_to_dataset[query_id] = dataset

    def remove_dataset(self, query_id: int):
        del self._query_id_to_dataset[query_id]

    @property
    def close_dataset(self) -> bool:
        return True

    @close_dataset.setter
    def set_close_dataset(self, session_id: int, query_id: int):
        release_query_resource(query_id)
        if session_id in self._session_id_to_statement_id:
            statement_id_set = self.get_statement_ids(session_id)
            for query_id_set in self.get_query_ids(statement_id_set):
                for query_id in query_id_set:
                    release_query_resource_no_exceptions(query_id)

    def get_statement_ids(self, session_id: int) -> Set[int]:
        return set()

    def get_query_ids(self, statement_id_set: Set[int]) -> Dict[int, Set[int]]:
        return {}

class QueryResourceManager:
    _instance = None

    @classmethod
    def getInstance(cls):
        if cls._instance is None:
            cls._instance = SessionManager()
        return cls._instance

    def assign_query_id(self) -> int:
        # implement your logic here
        pass
