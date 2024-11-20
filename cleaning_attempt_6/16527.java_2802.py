import threading
from collections import defaultdict, OrderedDict

class ClusterQueryManager:
    def __init__(self):
        self.id_atom = threading.AtomicLong(0)
        self.query_context_map = defaultdict(dict)
        self.series_reader_map = defaultdict(OrderedDict)
        self.series_reader_by_timestamp_map = defaultdict(OrderedDict)
        self.aggr_reader_map = defaultdict(OrderedDict)
        self.groupby_executor_map = defaultdict(OrderedDict)

    def get_query_context(self, node: 'Node', query_id: int) -> dict:
        if not self.query_context_map[node]:
            self.query_context_map[node] = {}
        return {query_id: RemoteQueryContext(QueryResourceManager().assign_query_id(True))}

    def register_reader(self, reader: 'IBatchReader') -> int:
        new_reader_id = self.id_atom.increment()
        self.series_reader_map[new_reader_id] = reader
        return new_reader_id

    def register_reader_by_time(self, reader_by_timestamp: 'IReaderByTimestamp') -> int:
        new_reader_id = self.id_atom.increment()
        self.series_reader_by_timestamp_map[new_reader_id] = reader_by_timestamp
        return new_reader_id

    @staticmethod
    def end_query(node: 'Node', query_id: int) -> None:
        if not self.query_context_map[node]:
            return
        remote_query_context = self.query_context_map[node].pop(query_id, None)
        if remote_query_context is None:
            return
        # release file resources
        QueryResourceManager().end_query(remote_query_context.get_query_id())

    def get_reader(self, reader_id: int) -> 'IBatchReader':
        return self.series_reader_map[reader_id]

    def get_reader_by_timestamp(self, reader_id: int) -> 'IReaderByTimestamp':
        return self.series_reader_by_timestamp_map[reader_id]

    @staticmethod
    def end_all_queries() -> None:
        for context_map in self.query_context_map.values():
            for remote_query_context in context_map.values():
                QueryResourceManager().end_query(remote_query_context.get_query_id())
        self.series_reader_by_timestamp_map.clear()
        self.series_reader_map.clear()
        self.aggr_reader_map.clear()

    def register_aggr_reader(self, aggregate_reader: 'IAggregateReader') -> int:
        new_reader_id = self.id_atom.increment()
        self.aggr_reader_map[new_reader_id] = aggregate_reader
        return new_reader_id

    @staticmethod
    def get_groupby_executor(executor_id: int) -> 'GroupByExecutor':
        return self.groupby_executor_map[executor_id]

    def register_group_by_executor(self, groupby_executor: 'GroupByExecutor') -> int:
        new_executor_id = self.id_atom.increment()
        self.groupby_executor_map[new_executor_id] = groupby_executor
        return new_executor_id

class Node:
    pass

class RemoteQueryContext:
    def __init__(self, query_id):
        self.query_id = query_id

    @staticmethod
    def assign_query_id(should_assign: bool) -> int:
        # TO DO: implement this method
        pass

class QueryResourceManager:
    @staticmethod
    def getInstance() -> 'QueryResourceManager':
        return None  # TO DO: implement this method

    @staticmethod
    def end_query(query_id: int) -> None:
        # TO DO: implement this method
        pass

    @staticmethod
    def assign_query_id(should_assign: bool) -> int:
        # TO DO: implement this method
        pass
