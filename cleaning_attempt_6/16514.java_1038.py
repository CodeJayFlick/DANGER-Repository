class ClusterUDTFQueryExecutor:
    def __init__(self, udtf_plan: 'UDTFPlan', meta_group_member: 'MetaGroupMember'):
        self.udtf_plan = udtf_plan
        self.meta_group_member = meta_group_member

    def execute_without_value_filter_align_by_time(self, context):
        readers_of_selected_series = self.init_managed_series_reader(context)
        return UDTFAlignByTimeDataSet(context, self.udtf_plan, readers_of_selected_series)

    def execute_with_value_filter_align_by_time(self, context):
        timestamp_generator = self.get_time_generator(context, self.udtf_plan)
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
        timestamp_generator = self.get_time_generator(context, self.udtf_plan)
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

    def get_time_generator(self, context: 'QueryContext', udtf_plan: 'UDTFPlan'):
        # implement this method in Python

    def mark_filtered_paths(expression, deduplicated_paths, has_or_node):
        # implement this method in Python

    def init_series_reader_by_timestamp(context, udf_plan, cached):
        # implement this methods in Python
