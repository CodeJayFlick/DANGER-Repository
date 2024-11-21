class RecorderThreadMap:
    def __init__(self):
        self.observed_thread_path_lengths = set()
        self.by_target_thread = {}
        self.by_trace_thread = {}

    def put(self, rec):
        path_length = len(rec.get_target_thread().get_path())
        self.observed_thread_path_lengths.add(path_length)
        self.by_target_thread[rec.get_target_thread()] = rec
        self.by_trace_thread[rec.get_trace_thread()] = rec

    # def get_for_successor(self, successor):  # not translated as it's commented out in the original code

    def get(self, thread):
        return self.by_target_thread.get(thread)

    def get(self, maybe_thread):
        return self.by_target_thread.get(maybe_thread)

    def get(self, trace_thread):
        return self.by_trace_thread.get(trace_thread)

    def remove(self, rec):
        r_by_target = self.by_target_thread.pop(rec.get_target_thread(), None)
        r_by_trace = self.by_trace_thread.pop(rec.get_trace_thread(), None)
        assert rec == r_by_target
        assert rec == r_by_trace

    def recorders(self):
        return list(self.by_target_thread.values())
