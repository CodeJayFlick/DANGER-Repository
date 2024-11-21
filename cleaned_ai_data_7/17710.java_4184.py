class SlidingWindowEvaluationHandler:
    def __init__(self, configuration: dict, evaluator):
        self.configuration = configuration
        self.evaluator = evaluator
        self.data = {}
        self.max_time = float('-inf')

    def create_evaluation_task_if_necessary(self, timestamp):
        pass  # abstract method

    def collect(self, timestamp, value):
        if timestamp <= self.max_time:
            return
        self.max_time = timestamp
        self.data[timestamp] = value
        self.create_evaluation_task_if_necessary(timestamp)

# Example usage:

configuration = {'data_type': 'int'}
evaluator = None  # Replace with your actual evaluator

handler = SlidingWindowEvaluationHandler(configuration, evaluator)
handler.collect(1, 10)  # Collects an integer value at timestamp 1
handler.collect(2, 20)  # Collects another integer value at timestamp 2
