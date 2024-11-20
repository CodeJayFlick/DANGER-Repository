Here is the translation of the Java code to Python:

```Python
class ClusterFillExecutor:
    def __init__(self, plan: 'FillQueryPlan', meta_group_member):
        self.meta_group_member = meta_group_member
        self.cluster_reader_factory = ClusterReaderFactory(meta_group_member)
        super().__init__(plan)

    def configure_fill(self, fill: 'IFill', path: PartialPath, data_type: TSDataType, query_time: int, device_measurements: set, context):
        if isinstance(fill, LinearFill):
            cluster_fill = ClusterLinearFill((fill), self.meta_group_member)
            return cluster_fill.configure_fill(path, data_type, query_time, device_measurements, context)

        elif isinstance(fill, PreviousFill):
            cluster_fill = ClusterPreviousFill((fill), self.meta_group_member)
            return cluster_fill.configure_fill(path, data_type, query_time, device_measurements, context)

        else:
            fill.configure_fill(path, data_type, query_time, device_measurements, context)
            return fill

    def get_time_value_pairs(self, context):
        ret = []
        for path in self.selected_series:
            data_type = self.data_types[self.selected_series.index(path)]
            reader = self.cluster_reader_factory.get_reader_by_timestamp(
                path,
                self.plan.get_all_measurements_in_device(path.device),
                data_type,
                context,
                self.plan.is_ascending(),
                None
            )
            results = reader.get_values_in_timestamps([query_time], 1)
            if results[0] is not None:
                ret.append(TimeValuePair(query_time, TsPrimitiveType.get_by_type(data_type, results[0])))
            else:
                ret.append(None)

        return ret

class ClusterReaderFactory:
    def __init__(self, meta_group_member):
        self.meta_group_member = meta_group_member
```

Note: This translation assumes that the Java classes and interfaces are equivalent to their Python counterparts.