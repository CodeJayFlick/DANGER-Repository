import threading

class DLR_EngineProvider:
    _engine = None  # NOPMD equivalent in Python

    def get_engine_name(self):
        return "DlrEngine"

    def get_engine_rank(self):
        return 1

    def get_engine(self):
        if self._engine is None:
            engine_lock = threading.Lock()
            with engine_lock:
                if self._engine is None:
                    from djl.engine import DLR_Engine
                    self._engine = DLR_Engine.new_instance()
        return self._engine


# Example usage:

provider = DLR_EngineProvider()

print(provider.get_engine_name())  # prints: "DlrEngine"
print(provider.get_engine_rank())   # prints: 1

if provider.get_engine() is None:
    print("No engine instance created yet.")
else:
    print("An engine instance has been created already.")

