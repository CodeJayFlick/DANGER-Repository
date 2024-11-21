class TracingInfo:
    def __init__(self):
        self.start_time = None
        self.series_path_num = 0
        self.seq_file_set = set()
        self.unseq_file_set = set()
        self.sequence_chunk_num = 0
        self.sequence_chunk_point_num = 0
        self.unsequence_chunk_num = 0
        self.unsequence_chunk_point_num = 0
        self.total_page_num = 0
        self.overlapped_page_num = 0
        self.activity_list = []

    def set_start_time(self, start_time):
        self.start_time = start_time

    def get_start_time(self):
        return self.start_time

    def add_chunk_info(self, chunk_num, point_num, is_seq):
        if is_seq:
            self.sequence_chunk_num += chunk_num
            self.sequence_chunk_point_num += point_num
        else:
            self.unsequence_chunk_num += chunk_num
            self.unsequence_chunk_point_num += point_num

    def get_sequence_chunk_num(self):
        return self.sequence_chunk_num

    def get_sequence_chunk_points(self):
        return self.sequence_chunk_point_num

    def get_unsequence_chunk_num(self):
        return self.unsequence_chunk_num

    def get_unsequence_chunk_points(self):
        return self.unsequence_chunk_point_num

    def add_ts_file_set(self, seq_resources, unseq_resources):
        self.seq_file_set.update(seq_resources)
        self.unseq_file_set.update(unseq_resources)

    def get_seq_file_set(self):
        return self.seq_file_set

    def get_unseq_file_set(self):
        return self.unseq_file_set

    def add_total_page_num(self, total_page_num):
        self.total_page_num += total_page_num

    def add_overlapped_page_num(self):
        self.overlapped_page_num += 1

    def add_activity(self, activity, time):
        self.activity_list.append((activity, time - self.start_time))

    def fill_rpc_return_tracing_info(self):
        ts_tracing_info = TSTracingInfo()
        
        activity_list = []
        elapsed_time_list = []

        for pair in self.activity_list:
            activity, elapsed_time = pair
            activity_list.append(activity)
            elapsed_time_list.append(elapsed_time)

        ts_tracing_info.set_activity_list(activity_list)
        ts_tracing_info.set_elapsed_time_list(elapsed_time_list)

        ts_tracing_info.set_series_path_num(self.series_path_num)
        ts_tracing_info.set_seq_file_num(len(self.seq_file_set))
        ts_tracing_info.set_unseq_file_num(len(self.unseq_file_set))
        ts_tracing_info.set_sequence_chunk_num(self.sequence_chunk_num)
        ts_tracing_info.set_sequence_chunk_point_num(self.sequence_chunk_point_num)
        ts_tracing_info.set_unsequence_chunk_num(self.unsequence_chunk_num)
        ts_tracing_info.set_unsequence_chunk_point_num(self.unsequence_chunk_point_num)
        ts_tracing_info.set_total_page_num(self.total_page_num)
        ts_tracing_info.set_overlapped_page_num(self.overlapped_page_num)

        return ts_tracing_info
