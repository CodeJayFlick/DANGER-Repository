import os
from typing import List, Tuple, Dict, Any

class BaseModel:
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.block = None
        self.manager = None
        self.data_type = None
        self.input_data = []
        self.artifacts = {}
        self.properties = {}

    @property
    def block(self) -> Any:
        return self._block

    @block.setter
    def block(self, value: Any):
        self._block = value

    @property
    def data_type(self) -> Any:
        return self._data_type

    @data_type.setter
    def data_type(self, value: Any):
        self._data_type = value

    @property
    def input_data(self) -> List[Tuple[str, int]]:
        return self._input_data

    @input_data.setter
    def input_data(self, value: List[Tuple[str, int]]):
        self._input_data = value

    @property
    def artifacts(self) -> Dict[str, Any]:
        return self._artifacts

    @artifacts.setter
    def artifacts(self, value: Dict[str, Any]):
        self._artifacts = value

    @property
    def properties(self) -> Dict[str, str]:
        return self._properties

    @properties.setter
    def properties(self, value: Dict[str, str]):
        self._properties = value

    def get_block(self):
        return self.block

    def set_block(self, block: Any):
        self.block = block

    def get_data_type(self) -> Any:
        return self.data_type

    def set_data_type(self, data_type: Any):
        self.data_type = data_type

    def describe_input(self) -> List[Tuple[str, int]]:
        if not self.input_data:
            self.input_data = self.block.describe_input()
        return self.input_data

    def get_artifacts_names(self) -> List[str]:
        raise NotImplementedError("Not supported!")

    def get_artifact(self, name: str, func: Any) -> Any:
        try:
            artifact = self.artifacts.get(name)
            if not isinstance(artifact, bytes):
                with open(os.path.join(self.model_dir, name), 'rb') as f:
                    artifact = f.read()
            return func(artifact)
        except Exception as e:
            raise IOError(str(e))

    def get_model_path(self) -> str:
        return self.model_dir

    def set_model_dir(self, model_dir: str):
        self.model_dir = os.path.abspath(model_dir)

    def save(self, path: str, new_name: str) -> None:
        if not new_name or not new_name.strip():
            new_name = self.model_name
        epoch_value = self.properties.get("Epoch")
        epoch = int(epoch_value) + 1 if epoch_value else Utils.getCurrentEpoch(path, new_name)
        file_name = f"{new_name}-{epoch:04d}.params"
        param_file = os.path.join(path, file_name)
        with open(param_file, 'wb') as f:
            f.write(b"DJL@\0\0")
            f.write(int.to_bytes(MODEL_VERSION, 4, "big"))
            f.write(new_name.encode("utf-8") + b"\0")
            self.data_type.encode(f, "utf-8")
            for desc in self.input_data:
                name = desc[0]
                if not name:
                    f.write(b"")
                else:
                    f.write(name.encode("utf-8"))
                f.write(desc[1].encode("utf-8"))
            f.write(int.to_bytes(len(self.properties), 4, "big") + b"\0")
            for key, value in self.properties.items():
                f.write(key.encode("utf-8"))
                f.write(value.encode("utf-8"))
            self.block.save_parameters(f)
        self.model_dir = os.path.abspath(path)

    def __str__(self) -> str:
        sb = StringBuilder(200)
        sb.append(f"Model (\n\tName: {self.model_name}")
        if self.model_dir:
            sb.append(f"\n\tModel location: {os.path.abspath(self.model_dir)}")
        sb.append(f"\n\tData Type: {self.data_type}\n)")
        for key, value in self.properties.items():
            sb.append(f"\n\t{key}: {value}")
        return str(sb)

    def __del__(self):
        if self.manager and self.manager.is_open:
            logger.warn("Model {} was not closed explicitly.".format(self.model_name))
            self.manager.close()
