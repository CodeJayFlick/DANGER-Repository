import threading

class TFLiteEngineProvider:
    _engine = None  # NOPMD equivalent in Python

    def get_engine_name(self):
        return "TfLiteEngine"

    def get_engine_rank(self):
        return 1  # assuming RANK is an integer constant, set it to a default value of 1

    def get_engine(self):
        if self._engine is None:
            lock = threading.Lock()
            with lock:
                if self._engine is None:
                    self._engine = TFLiteEngine().new_instance()
        return self._engine
