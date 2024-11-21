class SlidingTimeWindowEvaluationHandler:
    def __init__(self, configuration: dict, evaluator):
        self.time_interval = configuration['timeInterval']
        self.sliding_step = configuration['slidingStep']

        # Initialize queue for storing window begin indices.
        from collections import deque
        self.window_begin_index_queue = deque()

        self.current_window_end_time = 0
        self.next_window_begin_time = 0

    def create_evaluation_task_if_necessary(self, timestamp):
        if len(data) == 1:
            self.window_begin_index_queue.append(0)
            self.current_window_end_time = timestamp + self.time_interval
            self.next_window_begin_time = timestamp + self.sliding_step
            return

        while self.next_window_begin_time <= timestamp:
            self.window_begin_index_queue.append(len(data) - 1)
            self.next_window_begin_time += self.sliding_step

        while self.current_window_end_time <= timestamp:
            window_begin_index = self.window_begin_index_queue.popleft()
            task_pool_manager.submit(
                WindowEvaluationTask(self.evaluator, 
                                      WindowImpl(data, window_begin_index, len(data) - 1 - window_begin_index))
            )
            data.set_eviction_upper_bound(window_begin_index)
            self.current_window_end_time += self.sliding_step
