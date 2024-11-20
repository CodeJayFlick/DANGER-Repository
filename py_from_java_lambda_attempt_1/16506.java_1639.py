Here is the translation of the Java code to Python:

```Python
class ClusterAggregateExecutor:
    def __init__(self, context: 'QueryContext', aggregation_plan: 'AggregationPlan', meta_member: 'MetaGroupMember'):
        self.meta_member = meta_member
        self.reader_factory = ClusterReaderFactory(meta_member)
        self.aggregator = ClusterAggregator(meta_member)

    def aggregate_one_series(self,
                               series_path: 'PartialPath',
                               indexes: List[int],
                               all_measurements_in_device: Set[str],
                               time_filter: Filter) -> None:
        ts_data_type = data_types.get(indexes[0])
        aggregation_names = []

        for i in indexes:
            aggregation_names.append(aggregations[i])

        aggregate_result = self.aggregator.get_aggregate_result(
            series_path,
            all_measurements_in_device,
            aggregation_names,
            ts_data_type,
            time_filter,
            context,
            ascending
        )
        rst_index = 0

        for i in indexes:
            self.aggregate_result_list[i] = aggregate_result[rst_index]
            rst_index += 1

    def get_time_generator(self, context: 'QueryContext', raw_data_query_plan: 'RawDataQueryPlan') -> TimeGenerator:
        return ClusterTimeGenerator(context, self.meta_member, raw_data_query_plan, False)

    def get_reader_by_time(self,
                            path: 'PartialPath',
                            data_query_plan: 'RawDataQueryPlan',
                            data_type: TSDataType,
                            context: 'QueryContext') -> IReaderByTimestamp:
        return self.reader_factory.get_reader_by_timestamp(
            path,
            data_query_plan.get_all_measurements_in_device(path.get_device()),
            data_type,
            context,
            data_query_plan.is_ascending(),
            None
        )
```

Note that Python does not have direct equivalent of Java's static type system. The types are inferred by the interpreter at runtime, and can be changed dynamically.