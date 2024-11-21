class PathNumOverLimitException(Exception):
    def __init__(self, max_query_deduplicated_path_num):
        message = f"Too many paths in one query! Currently allowed max deduplicated path number is {max_query_deduplicated_path_num}. Please use slimit or adjust max_deduplicated_path_num in iotdb-engine.properties."
        super().__init__(message)
