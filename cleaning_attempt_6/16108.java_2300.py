import os
from typing import Dict, Any

class TfLiteModel:
    def __init__(self, name: str, manager):
        self.name = name
        self.manager = manager
        self.data_type = 'FLOAT32'

    def load(self, model_path: str, prefix: str, options: Dict[str, Any]) -> None:
        if os.path.exists(model_path) and not os.path.isdir(model_path):
            raise FileNotFoundError(f"TFLite model file not found in {model_path}")
        
        for root, dirs, files in os.walk(model_path):
            for file in files:
                if file.endswith('.tflite'):
                    self.model_file = os.path.join(root, file)
                    break
            else:
                continue
            break
        
        interpreter = Interpreter(self.model_file)
        block = TfLiteSymbolBlock(interpreter, self.manager)

    def get_nd_manager(self) -> 'TfLiteNDManager':
        return self.manager

    def close(self):
        if hasattr(self, 'block'):
            self.block.close()
            del self.block
