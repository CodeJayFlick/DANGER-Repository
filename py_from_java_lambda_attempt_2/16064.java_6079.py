Here is the translation of the given Java code into equivalent Python:

```Python
import os
from tensorflow import ConfigProto, RunOptions
from typing import List, Dict, Any

class TfModel:
    DEFAULT_SERVING_SIGNATURE_DEF_KEY = "serving_default"

    def __init__(self, name: str, device):
        self.name = name
        self.device = device
        self.properties = {}
        self.manager = None

    def load(self, model_path: str, prefix: str, options: Dict[str, Any]) -> None:
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"No TensorFlow model found in {model_path}")

        export_dir = find_model_dir(os.path.abspath(model_path), prefix)
        if export_dir is None:
            return

        tags = None
        config_proto = None
        run_options = None
        signature_def_key = self.DEFAULT_SERVING_SIGNATURE_DEF_KEY

        if options:
            tag_option = options.get("Tags")
            if isinstance(tag_option, str):
                tags = [tag_option]
            elif isinstance(tag_option, list):
                tags = tag_option
            config_proto_option = options.get("ConfigProto")
            if isinstance(config_proto_option, ConfigProto):
                config_proto = config_proto_option
            else:
                try:
                    buf = base64.b64decode(str(config_proto_option))
                    config_proto = ConfigProto()
                    config_proto.ParseFromString(buf)
                except Exception as e:
                    raise MalformedModelException(f"Invalid ConfigProto: {config_proto_option}", e)

            run_options_option = options.get("RunOptions")
            if isinstance(run_options_option, RunOptions):
                run_options = run_options_option
            else:
                try:
                    buf = base64.b64decode(str(run_options_option))
                    run_options = RunOptions()
                    run_options.ParseFromString(buf)
                except Exception as e:
                    raise MalformedModelException(f"Invalid RunOptions: {run_options_option}", e)

        if "SignatureDefKey" in options:
            signature_def_key = str(options["SignatureDefKey"])

        bundle = JavacppUtils.load_saved_model_bundle(export_dir, tags, config_proto, run_options)
        self.block = TfSymbolBlock(bundle, signature_def_key)


    def find_model_dir(self, prefix: str) -> Path:
        path = os.path.join(os.getcwd(), prefix)
        if not os.path.exists(path):
            return None

        if os.path.isfile(path):
            return os.getcwd()
        elif os.path.isdir(path):
            file_path = os.path.join(path, "saved_model.pb")
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return path
        return None


    def save(self, model_path: str, new_model_name: str) -> None:
        raise NotImplementedError("Not supported for TensorFlow Engine")


    @property
    def block(self) -> Any:
        return self._block

    @block.setter
    def block(self, value: Any):
        if not isinstance(value, TfSymbolBlock):
            raise ValueError(f"Only {TfSymbolBlock} is allowed")
        self._block = value


    @property
    def nd_manager(self) -> Any:
        return self.manager

    @nd_manager.setter
    def nd_manager(self, value: Any):
        if not isinstance(value, NDManager):
            raise ValueError(f"Only {NDManager} is allowed")
        self.manager = value


    def get_artifact_names(self) -> List[str]:
        try:
            files = [os.path.join(os.getcwd(), f.name) for f in os.listdir() if f.endswith(".pb")]
            return files
        except Exception as e:
            raise AssertionError("Failed list files", e)


    def close(self):
        if self.block is not None:
            (self.block).close()
            self.block = None
        super().close()

class TfSymbolBlock:
    # implementation of block

def JavacppUtils():
    # implementation of javacpputils


if __name__ == "__main__":
    pass
```

Please note that the given Java code is part of a larger system and may not be directly translatable to Python. This translation assumes that you have equivalent classes in your Python environment, such as `NDManager` and `TfSymbolBlock`.