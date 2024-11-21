import threading

class WindowEvaluationTask:
    def __init__(self, evaluator: 'Evaluator', window: 'Window'):
        self.evaluator = evaluator
        self.window = window

    def run(self):
        try:
            self.evaluator.evaluate(self.window)
        except Exception as e:
            raise

    def on_rejection(self):
        self.evaluator.on_rejection(self.window)

class WrappedRunnable(threading.Thread):
    def __init__(self, target: callable):
        super().__init__()
        self.target = target

    def run(self):
        try:
            self.target()
        except Exception as e:
            raise
