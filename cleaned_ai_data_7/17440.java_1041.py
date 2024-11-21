class UDTFQueryExecutor:
    def __init__(self, udtf_plan):
        self.udtf_plan = udtf_plan

    def execute_without_value_filter_align_by_time(self, context):
        readers_of_selected_series = self.init_managed_series_reader(context)
        return UDTFAlignByTimeDataSet(context, self.udtf_plan, readers_of_selected_series)

    def execute_with_value_filter_align_by_time(self, context):
        timestamp_generator = self.get_timestamp_generator(context, self.udtf_plan)
        cached = mark_filtered_paths(
            self.udtf_plan.expression,
            list(self.udtf_plan.deduplicated_paths),
            timestamp_generator.has_or_node()
        )
        readers_of_selected_series = self.init_series_reader_by_timestamp(context, self.udtf_plan, cached)
        return UDTFAlignByTimeDataSet(
            context, 
            self.udtf_plan, 
            timestamp_generator, 
            readers_of_selected_series, 
            cached
        )

    def execute_without_value_filter_non_align(self, context):
        readers_of_selected_series = self.init_managed_series_reader(context)
        return UDTFNonAlignDataSet(context, self.udtf_plan, readers_of_selected_series)

    def execute_with_value_filter_non_align(self, context):
        timestamp_generator = self.get_timestamp_generator(context, self.udtf_plan)
        cached = mark_filtered_paths(
            self.udtf_plan.expression,
            list(self.udtf_plan.deduplicated_paths),
            timestamp_generator.has_or_node()
        )
        readers_of_selected_series = self.init_series_reader_by_timestamp(context, self.udtf_plan, cached)
        return UDTFNonAlignDataSet(
            context, 
            self.udtf_plan, 
            timestamp_generator, 
            readers_of_selected_series, 
            cached
        )

    def init_managed_series_reader(self, context):
        # implement this method in Python
        pass

    def get_timestamp_generator(self, context, udtf_plan):
        # implement this method in Python
        pass

    def mark_filtered_paths(expression, deduplicated_paths, has_or_node):
        # implement this method in Python
        pass

    def init_series_reader_by_timestamp(self, context, udf_plan, cached):
        # implement this methods in Python
        pass


class UDTFAlignByTimeDataSet:
    def __init__(self, context, udtf_plan, readers_of_selected_series):
        self.context = context
        self.udtf_plan = udtf_plan
        self.readers_of_selected_series = readers_of_selected_series

class UDTFNonAlignDataSet:
    def __init__(self, context, udf_plan, timestamp_generator, readers_of_selected_series, cached):
        self.context = context
        self.udft_plan = udf_plan
        self.timestamp_generator = timestamp_generator
        self.readers_of_selected_series = readers_of_selected_series
        self.cached = cached

