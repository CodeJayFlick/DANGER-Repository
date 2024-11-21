Here's your Java code translated into Python:

```Python
class ServerTimeGenerator:
    def __init__(self, context):
        self.context = context

    def server_construct_node(self, expression):
        path_list = []
        self.get_partial_path_from_expression(expression, path_list)
        list_ = StorageEngine().merge_lock(path_list)
        try:
            operator_node = construct(expression)
        finally:
            StorageEngine().merge_unlock(list_)

    def get_partial_path_from_expression(self, expression, path_list):
        if isinstance(expression, SingleSeriesExpression):
            path_list.append((expression.get_series_path()))
        else:
            self.get_partial_path_from_expression(((IBinaryExpression)(expression)).get_left(), path_list)
            self.get_partial_path_from_expression(((IBinaryExpression)(expression)).get_right(), path_list)

    def generate_new_batch_reader(self, expression):
        value_filter = expression.get_filter()
        path = (expression.get_series_path())
        data_type; query_data_source
        try:
            data_type = IoTDB().meta_manager.get_series_type(path)
            query_data_source = QueryResourceManager().get_query_data_source(path, self.context, value_filter)
            # update valueFilter by TTL
            value_filter = query_data_source.update_filter_using_ttl(value_filter)
        except Exception as e:
            raise IOException(e)

        time_filter = self.get_time_filter(value_filter)

        return SeriesRawDataBatchReader(
            path,
            query_plan().get_all_measurements_in_device(path.get_device()),
            data_type,
            self.context,
            query_data_source,
            time_filter,
            value_filter,
            None,
            query_plan().is_ascending()
        )

    def get_time_filter(self, filter):
        if isinstance(filter, UnaryFilter) and ((UnaryFilter)(filter)).get_filter_type() == FilterType.TIME_FILTER:
            return filter
        elif isinstance(filter, AndFilter):
            left_time_filter = self.get_time_filter(((AndFilter)(filter)).get_left())
            right_time_filter = self.get_time_filter(((AndFilter)(filter)).get_right())
            if left_time_filter and right_time_filter:
                return filter
            elif left_time_filter:
                return left_time_filter
            else:
                return right_time_filter
        return None

    def is_ascending(self):
        return query_plan().is_ascending()
```

Note: I've used Python's built-in `list` type to replace Java's `ArrayList`. Also, the equivalent of Java's constructor with multiple parameters in Python would be a method.