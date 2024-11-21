class TimeSeriesOperand:
    def __init__(self, path):
        self.path = path

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

    def concat(self, prefix_paths, result_expressions):
        for prefix_path in prefix_paths:
            result_expressions.append(TimeSeriesOperand(prefix_path.concat_path(self.path)))

    def remove_wildcards(self, wildcards_remover, result_expressions):
        actual_paths = wildcards_remover.remove_wildcard_from(self.path)
        for actual_path in actual_paths:
            result_expressions.append(TimeSeriesOperand(actual_path))

    def collect_paths(self, path_set):
        path_set.add(self.path)

    def construct_udf_executors(self, expression_name2_executor, zone_id):
        pass

    def update_statistics_for_memory_assigner(self, memory_assigner):
        memory_assigner.increase_expression_reference(self)

    def construct_intermediate_layer(self, query_id, udtf_plan, raw_time_series_input_layer,
                                       expression_intermediate_layer_map, expression_data_type_map, memory_assigner):
        if self not in expression_intermediate_layer_map:
            memory_budget_in_mb = memory_assigner.assign()
            parent_layer_point_reader = (raw_time_series_input_layer.construct_point_reader(
                udtf_plan.get_reader_index(self.path.full_path())))
            expression_data_type_map[self] = parent_layer_point_reader.data_type

            if memory_assigner.reference_count_to_this_expression == 1:
                intermediate_layer = SingleInputColumnSingleReferenceIntermediateLayer(
                    self, query_id, memory_budget_in_mb, parent_layer_point_reader)
            else:
                intermediate_layer = SingleInputColumnMultiReferenceIntermediateLayer(
                    self, query_id, memory_budget_in_mb, parent_layer_point_reader)

            expression_intermediate_layer_map[self] = intermediate_layer

        return expression_intermediate_layer_map.get(self)

    def __str__(self):
        if self.path.is_measurement_alias_exists():
            return self.path.full_path_with_alias()
        else:
            return self.path.exact_full_path()


class SingleInputColumnSingleReferenceIntermediateLayer:
    pass


class SingleInputColumnMultiReferenceIntermediateLayer:
    pass
