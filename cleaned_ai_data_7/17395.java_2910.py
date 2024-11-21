class QueryFileManager:
    def __init__(self):
        self.sealed_file_paths_map = {}
        self.unsealed_file_paths_map = {}

    def add_query_id(self, query_id: int) -> None:
        if query_id not in self.sealed_file_paths_map:
            self.sealed_file_paths_map[query_id] = set()
        if query_id not in self.unsealed_file_paths_map:
            self.unsealed_file_paths_map[query_id] = set()

    def add_used_files_for_query(self, query_id: int, data_source: dict) -> None:
        sequence_data = data_source.get('sequence_resources', [])
        un_sequence_data = data_source.get('unsequence_resources', [])

        for resource in sequence_data + un_sequence_data:
            if not self.add_file_path_to_map(query_id, resource):
                break

    def add_file_path_to_map(self, query_id: int, ts_file_resource: dict, is_closed: bool) -> bool:
        path_map = self.sealed_file_paths_map if is_closed else self.unsealed_file_paths_maps
        if ts_file_resource not in path_map.get(query_id, set()):
            path_map[query_id].add(ts_file_resource)
            file_reader_manager().increase_file_reader_reference(ts_file_resource, is_closed)

    def remove_used_files_for_query(self, query_id: int) -> None:
        self.sealed_file_paths_map.pop(query_id, None)
        self.unsealed_file_paths_map.pop(query_id, None)


def file_reader_manager() -> object:
    pass
