import threading
from collections import defaultdict


class QueryResourceManager:
    def __init__(self):
        self.query_id_atom = 0
        self.file_paths_manager = FilePathsManager()
        self.external_sort_file_map = defaultdict(list)

    @classmethod
    def get_instance(cls):
        return cls()

    def assign_query_id(self, is_data_query=False):
        query_id = self.query_id_atom += 1
        if is_data_query:
            self.file_paths_manager.add_query_id(query_id)
        return query_id

    def register_temp_external_sort_file(self, query_id: int, deserializer) -> None:
        self.external_sort_file_map[query_id].append(deserializer)

    def get_query_data_source(
        self,
        selected_path: str,
        context: dict,
        filter: dict
    ) -> tuple:
        single_series_expression = SingleSeriesExpression(selected_path, filter)
        query_data_source = StorageEngine().query(single_series_expression, context, self.file_paths_manager)
        
        if context.get("enable_tracing"):
            TracingManager().add_ts_file_set(
                context["query_id"],
                query_data_source[0],
                query_data_source[1]
            )
            
        return query_data_source

    def end_query(self, query_id: int) -> None:
        if self.external_sort_file_map.get(query_id):
            for deserializer in self.external_sort_file_map[query_id]:
                try:
                    deserializer.close()
                except Exception as e:
                    raise StorageEngineException(e)
            
            del self.external_sort_file_map[query_id]
        
        self.file_paths_manager.remove_used_files_for_query(query_id)

        TemporaryQueryDataFileService().deregister(query_id)


class FilePathsManager:
    def __init__(self):
        self.query_ids = set()

    def add_query_id(self, query_id: int) -> None:
        self.query_ids.add(query_id)

    def remove_used_files_for_query(self, query_id: int) -> None:
        if query_id in self.query_ids:
            del self.query_ids


class SingleSeriesExpression:
    def __init__(self, selected_path: str, filter: dict):
        self.selected_path = selected_path
        self.filter = filter

    # Implement the logic for this class as needed.
