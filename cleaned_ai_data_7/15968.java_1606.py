import os
from onnxruntime import OrtSessionOptions, OrtEnvironment, OrtSession
from djl.basic.ndarray.NDManager import NDManager
from djl.basic.Model import Model
from djl.exceptions.MalformedModelException import MalformedModelException

class OrtModel(Model):
    def __init__(self, name: str, manager: NDManager, env: OrtEnvironment) -> None:
        super().__init__(name)
        self.manager = manager
        self.env = env
        self.data_type = "FLOAT32"

    def load(self, model_path: str, prefix: str, options: dict):
        try:
            if os.path.exists(model_path):
                device = self.manager.get_device()
                session_options = OrtSessionOptions()
                if device.is_gpu():
                    session_options.add_cuda(device.get_device_id())
                session = self.env.create_session(model_path, session_options)
                block = OrtSymbolBlock(session, self.manager)
        except Exception as e:
            raise MalformedModelException("ONNX Model cannot be loaded", e)

class OrtSymbolBlock:
    def __init__(self, session: OrtSession, manager: NDManager) -> None:
        self.session = session
        self.manager = manager

def find_model_file(prefix: str):
    if os.path.exists(model_dir):
        file_path = model_dir
        model_dir = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        if file_name.endswith(".onnx"):
            model_name = file_name[:-5]
        else:
            model_name = file_name
        return file_path

    if prefix is None:
        prefix = model_name

    model_file = os.path.join(model_dir, prefix)

    if not os.path.exists(model_file) or not os.path.isfile(model_file):
        if prefix.endswith(".onnx"):
            return None
        else:
            model_file += ".onnx"
            if not os.path.exists(model_file) or not os.path.isfile(model_file):
                return None

    return model_file
