Here is the translation of the given Java code into Python:

```Python
import os
from typing import Any, Dict, Tuple

class TrtModel:
    def __init__(self, name: str, manager):
        self.name = name
        self.manager = manager
        self.data_type = "FLOAT32"

    def load(self, model_path: str, prefix: str, options: Dict[str, Any]) -> None:
        if hasattr(self, 'block'):
            raise Exception("TensorRT does not support dynamic blocks")

        self.model_dir = os.path.abspath(model_path)
        if prefix is None:
            prefix = self.name

        for file in [f"{prefix}.onnx", f"{self.name}.onnx"]:
            model_file = os.path.join(self.model_dir, file)
            if os.path.exists(model_file) and os.path.isfile(model_file):
                break
        else:
            raise FileNotFoundError(f"File not found: {os.path.join(self.model_dir, prefix)}")

        self.block = TrtSymbolBlock(JniUtils.load_model(os.path.splitext(file)[1], model_file, self.manager.get_device(), options))

    def new_predictor(self, translator) -> Any:
        trt_symbol_block = self.block
        session = trt_symbol_block.create_session(self.manager)
        return TrtPredictor(self, translator, session)

class TrtSymbolBlock:
    def __init__(self, model_handle):
        self.model_handle = model_handle

    def create_session(self, manager) -> Any:
        # Implement this method
        pass

    def close(self) -> None:
        if hasattr(self, 'model_handle'):
            JniUtils.close_model(self.model_handle)
            del self.model_handle


class TrtPredictor:
    def __init__(self, model: TrtModel, translator, session):
        self.model = model
        self.translator = translator
        self.session = session

# Implement the following classes and methods in Python
JniUtils.load_model
TrtNDManager.get_device()
```

Note that some parts of this code are not directly translatable from Java to Python. For example, `JniUtils` seems to be a wrapper around native C++/Java functionality which is specific to Android/iOS development and might require additional setup in Python (e.g., using libraries like `ctypes`, `subprocess`, or `pyjnius`).