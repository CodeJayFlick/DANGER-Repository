Here is the translation of the given Java code into equivalent Python:

```Python
import os
from typing import Any, Dict, List, Tuple

class PpModel:
    def __init__(self, name: str, device: str = None) -> None:
        self.name = name
        if not device:
            self.device = "cpu"
        else:
            self.device = device

    def load(self, model_path: str, prefix: str, options: Dict[str, Any]) -> None:
        try:
            model_files = find_model_file(model_path)
            config = create_config(model_files[0], model_files[1], self.device)
            if options:
                for key, value in options.items():
                    if key == "remove_pass":
                        remove_pass(config, value.split(","))
                    elif key == "enable_mkldnn":
                        enable_mkldnn(config)
                    elif key == "disable_glog":
                        disable_glog(config)
                    elif key == "cml_num_threads":
                        cpu_math_library_num_threads(config, int(value))
                    elif key == "switch_ir_optim":
                        switch_ir_optim(config, bool(value))

            self.paddle_predictor = PaddlePredictor(create_predictor(config))
            delete_config(config)

        except FileNotFoundError as e:
            print(f"no __model__ or model file found in: {model_path}")
        except Exception as e:
            raise

    def new_predictor(self, translator) -> Any:
        return PpPredictor(self, self.paddle_predictor.copy(), translator)

    def close(self):
        if self.paddle_predictor is not None:
            delete_predictor(self.paddle_predictor)
            self.paddle_predictor = None
        super().close()

def find_model_file(dir: str) -> List[str]:
    model_files = []
    patterns = [
        ("model", "params"),
        ("__model__", "__params__"),
        ("inference.pdmodel", "inference.pdiparams")
    ]
    for pattern in patterns:
        file_path = os.path.join(dir, pattern[0])
        if os.path.isfile(file_path):
            model_files.append(file_path)
            param_file_path = os.path.join(dir, pattern[1])
            if os.path.isfile(param_file_path):
                return [file_path, param_file_path]
    return []

def create_config(model_file: str, param_file: str, device: str) -> Any:
    # Implement the logic to create a config based on model and parameter files
    pass

class PaddlePredictor:
    def __init__(self, predictor):
        self.predictor = predictor

    def copy(self):
        return PaddlePredictor(self.predictor)

def delete_config(config: Any) -> None:
    # Implement the logic to delete a config
    pass

def create_predictor(config: Any) -> Any:
    # Implement the logic to create a predictor based on the given config
    pass

class PpSymbolBlock:
    def __init__(self, paddle_predictor: PaddlePredictor, manager):
        self.paddle_predictor = paddle_predictor
        self.manager = manager

def delete_predictor(predictor: Any) -> None:
    # Implement the logic to delete a predictor
    pass

class Translator:
    pass

# Usage example:

model = PpModel("my_model", "gpu")
model.load("/path/to/model", "prefix", {"remove_pass": ["pass1", "pass2"]})
predictor = model.new_predictor(Translator())
```

Please note that the above Python code is a direct translation of the given Java code and may not be fully functional as it lacks implementation for certain methods like `create_config`, `delete_config`, `create_predictor`, etc.