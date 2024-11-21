Here is the translation of the Java code to Python:
```
import io

class UDFQueryRowWindowTransformer:
    def __init__(self, layer_row_window_reader: 'LayerRowWindowReader', executor):
        super().__init__(executor)
        self.layer_row_window_reader = layer_row_window_reader

    @property
    def layer_row_window_reader(self) -> 'LayerRowWindowReader':
        return self._layer_row_window_reader

    @layer_row_window_reader.setter
    def layer_row_window_reader(self, value: 'LayerRowWindowReader'):
        self._layer_row_window_reader = value

    def execute_udf_once(self):
        if not self.layer_row_window_reader.next():
            return False
        try:
            self.executor.execute(self.layer_row_window_reader.current_window())
        except (QueryProcessException, IOException) as e:
            raise e
        finally:
            self.layer_row_window_reader.ready_for_next()
        return True

class LayerRowWindowReader:
    def next(self):
        # implement your logic here
        pass

    def current_window(self):
        # implement your logic here
        pass

    def ready_for_next(self):
        # implement your logic here
        pass
```
Note that I've used Python's type hinting to indicate the types of variables and method parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've assumed that `UDTFExecutor` and other classes are defined elsewhere in the codebase or imported from external libraries. If you need help translating those as well, please let me know!