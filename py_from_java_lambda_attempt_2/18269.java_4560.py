Here is the translation of the given Java code into Python:

```Python
class ExecutorWithTimeGenerator:
    def __init__(self, metadata_querier: 'IMetadataQuerier', chunk_loader: 'IChunkLoader'):
        self.metadata_querier = metadata_querier
        self.chunk_loader = chunk_loader

    @staticmethod
    def mark_filtered_paths(expression: 'IExpression', selected_paths: list, has_or_node: bool) -> list:
        cached = []
        if has_or_node:
            for _ in range(len(selected_paths)):
                cached.append(False)
            return cached
        
        filtered_paths = set()
        ExecutorWithTimeGenerator._get_all_filtered_paths(expression, filtered_paths)

        for selected_path in selected_paths:
            cached.append(selected_path in filtered_paths)

        return cached

    @staticmethod
    def _get_all_filtered_paths(expression: 'IExpression', paths: set):
        if isinstance(expression, BinaryExpression):
            ExecutorWithTimeGenerator._get_all_filtered_paths(expression.get_left(), paths)
            ExecutorWithTimeGenerator._get_all_filtered_paths(expression.get_right(), paths)

        elif isinstance(expression, SingleSeriesExpression):
            paths.add(expression.get_series_path())

    def execute(self, query_expression: 'QueryExpression') -> 'DataSetWithTimeGenerator':
        expression = query_expression.expression
        selected_paths = query_expression.selected_series

        time_generator = TsFileTimeGenerator(expression, self.chunk_loader, self.metadata_querier)

        cached = ExecutorWithTimeGenerator.mark_filtered_paths(expression, selected_paths, has_or_node=time_generator.has_or_node())

        readers_of_selected_series = []
        data_types = []

        for value in cached:
            if not value:
                continue
            path = next((path for path in selected_paths), None)
            chunk_metadata_list = self.metadata_querier.get_chunk_meta_data_list(path)
            if len(chunk_metadata_list) != 0:
                data_type = chunk_metadata_list[0].get_data_type()
                readers_of_selected_series.append(None)
                continue
            series_reader = FileSeriesReaderByTimestamp(self.chunk_loader, chunk_metadata_list)
            readers_of_selected_series.append(series_reader)

        return DataSetWithTimeGenerator(selected_paths, cached, data_types, time_generator, readers_of_selected_series)


class QueryExpression:
    def __init__(self):
        pass

    @property
    def expression(self) -> 'IExpression':
        raise NotImplementedError()

    @property
    def selected_series(self) -> list:
        raise NotImplementedError()


class IChunkMetadata:
    def get_data_type(self) -> int:
        raise NotImplementedError


class IMetadataQuerier:
    def get_chunk_meta_data_list(self, path: str) -> list:
        raise NotImplementedError

    def has_or_node(self):
        return False
```

Please note that this is a direct translation of the given Java code into Python. It may not be optimal or idiomatic for Python and might require adjustments to work correctly in your specific use case.