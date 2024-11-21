class SingleInputColumnMultiReferenceIntermediateLayer:
    def __init__(self, expression, query_id, memory_budget_in_mb, parent_layer_point_reader):
        self.parent_layer_point_reader = parent_layer_point_reader
        self.data_type = parent_layer_point_reader.get_data_type()
        self.tv_list = ElasticSerializableTVList(self.data_type, query_id, memory_budget_in_mb)
        self.safety_line = SafetyLine()

    def construct_point_reader(self):
        return PointReader(self)

    class PointReader:
        def __init__(self, intermediate_layer):
            self.intermediate_layer = intermediate_layer
            self.has_cached = False
            self.current_point_index = -1

        def next(self):
            if not self.has_cached and (self.current_point_index < len(intermediate_layer.tv_list) - 1 or LayerCacheUtils.cache_point(intermediate_layer.data_type, intermediate_layer.parent_layer_point_reader, intermediate_layer.tv_list)):
                self.current_point_index += 1
                self.has_cached = True
            return self.has_cached

        def ready_for_next(self):
            self.has_cached = False
            self.intermediate_layer.safety_line.move_forward_to(self.current_point_index + 1)
            intermediate_layer.tv_list.set_eviction_upper_bound(intermediate_layer.safety_line.get_safety_line())

        def get_data_type(self):
            return self.intermediate_layer.data_type

        def current_time(self):
            return intermediate_layer.tv_list.time(self.current_point_index)

        def current_int(self):
            return intermediate_layer.tv_list.int_value(self.current_point_index)

        def current_long(self):
            return intermediate_layer.tv_list.long_value(self.current_point_index)

        def current_float(self):
            return intermediate_layer.tv_list.float_value(self.current_point_index)

        def current_double(self):
            return intermediate_layer.tv_list.double_value(self.current_point_index)

        def current_boolean(self):
            return intermediate_layer.tv_list.boolean_value(self.current_point_index)

        def current_binary(self):
            return intermediate_layer.tv_list.binary_value(self.current_point_index)


    def construct_row_reader(self):
        return RowReader(self)

    class RowReader:
        def __init__(self, intermediate_layer):
            self.intermediate_layer = intermediate_layer
            self.has_cached = False
            self.current_row_index = -1

        def next(self):
            if not self.has_cached and (self.current_row_index < len(intermediate_layer.tv_list) - 1 or LayerCacheUtils.cache_point(intermediate_layer.data_type, intermediate_layer.parent_layer_point_reader, intermediate_layer.tv_list)):
                row = ElasticSerializableTVListBackedSingleColumnRow(intermediate_layer.tv_list)
                row.seek(self.current_row_index + 1)
                self.has_cached = True
            return self.has_cached

        def ready_for_next(self):
            self.has_cached = False
            self.intermediate_layer.safety_line.move_forward_to(self.current_row_index + 1)
            intermediate_layer.tv_list.set_eviction_upper_bound(intermediate_layer.safety_line.get_safety_line())

        def get_data_types(self):
            return [intermediate_layer.data_type]

        def current_time(self):
            return row.time()

        def current_row(self):
            return row


    def construct_sliding_size_window_reader(self, strategy, memory_budget_in_mb):
        window = ElasticSerializableTVListBackedSingleColumnWindow(intermediate_layer.tv_list)
        safety_pile = self.intermediate_layer.safety_line.add_safety_pile()
        begin_index = -strategy.get_sliding_step()

        return SlidingSizeWindowReader(self)

    class SlidingSizeWindowReader:
        def __init__(self, intermediate_layer):
            self.intermediate_layer = intermediate_layer
            self.has_cached = False
            self.begin_index = 0

        def next(self):
            if not self.has_cached and (len(intermediate_layer.tv_list) <= begin_index or LayerCacheUtils.cache_points(intermediate_layer.data_type, intermediate_layer.parent_layer_point_reader, intermediate_layer.tv_list)):
                window.seek(begin_index + strategy.get_sliding_step(), len(intermediate_layer.tv_list))
                self.has_cached = True
            return self.has_cached

        def ready_for_next(self):
            self.has_cached = False
            safety_pile.move_forward_to(begin_index + 1)
            intermediate_layer.tv_list.set_eviction_upper_bound(intermediate_layer.safety_line.get_safety_line())

        def get_data_types(self):
            return [intermediate_layer.data_type]

        def current_window(self):
            return window


    def construct_sliding_time_window_reader(self, strategy, memory_budget_in_mb):
        time_interval = strategy.get_time_interval()
        sliding_step = strategy.get_sliding_step()

        safety_pile = self.intermediate_layer.safety_line.add_safety_pile()
        window = ElasticSerializableTVListBackedSingleColumnWindow(intermediate_layer.tv_list)

        return SlidingTimeWindowReader(self)

    class SlidingTimeWindowReader:
        def __init__(self, intermediate_layer):
            self.intermediate_layer = intermediate_layer
            self.has_cached = False
            self.next_window_time_begin = strategy.get_display_window_begin()
            self.next_index_begin = 0

        def next(self):
            if not self.has_cached and (len(intermediate_layer.tv_list) == 0 or display_window_end <= self.next_window_time_begin):
                return False
            for i in range(next_index_begin, len(intermediate_layer.tv_list)):
                if self.next_window_time_begin <= intermediate_layer.tv_list.time(i):
                    next_index_begin = i
                    break
                elif i == len(intermediate_layer.tv_list) - 1:
                    next_index_begin = len(intermediate_layer.tv_list)
            for i in range(next_index_begin, len(intermediate_layer.tv_list)):
                if self.next_window_time_end <= intermediate_layer.tv_list.time(i):
                    next_index_end = i
                    break

            window.seek(next_index_begin, next_index_end)

            has_cached = next_index_begin != next_index_end
            return has_cached

        def ready_for_next(self):
            self.has_cached = False
            self.next_window_time_begin += sliding_step

            safety_pile.move_forward_to(next_index_begin + 1)
            intermediate_layer.tv_list.set_eviction_upper_bound(intermediate_layer.safety_line.get_safety_line())

        def get_data_types(self):
            return [intermediate_layer.data_type]

        def current_window(self):
            return window
