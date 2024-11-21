import concurrent.futures

class Evaluator:
    def evaluate(self, window: 'Window') -> None:
        raise Exception()

    def on_rejection(self, window: 'Window') -> None:
        raise concurrent.futuresRejectedExecutionException()
