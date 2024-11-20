import ctypes
from typing import List

class FtWrapper:
    def __init__(self):
        self.handle = FastTextLibrary.create_fasttext()

    @staticmethod
    def new_instance():
        if library_status:
            raise library_status
        return FtWrapper()

    def load_model(self, model_file_path: str) -> None:
        FastTextLibrary.load_model(self.handle, model_file_path)

    def check_model(self, model_file_path: str) -> bool:
        return FastTextLibrary.check_model(model_file_path)

    def unload_model(self) -> None:
        FastTextLibrary.unload_model(self.handle)

    def get_model_type(self) -> str:
        return FastTextLibrary.get_model_type(self.handle)

    def predict_proba(self, text: str, top_k: int, label_prefix: str) -> 'Classifications':
        labels = [''] * top_k
        probs = [0.0] * top_k

        size = FastTextLibrary.predict_proba(self.handle, text, top_k, labels, probs)

        classes = []
        probabilities = []
        for i in range(size):
            label = labels[i]
            if label.startswith(label_prefix):
                label = label[len(label_prefix):]
            classes.append(label)
            probabilities.append(float(probs[i]))

        return Classifications(classes, probabilities)

    def get_data_vector(self, word: str) -> List[float]:
        return FastTextLibrary.get_word_vector(self.handle, word)

    @staticmethod
    def run_cmd(args: List[str]) -> None:
        FastTextLibrary.run_cmd(args)


class Classifications:
    def __init__(self, classes: List[str], probabilities: List[float]):
        self.classes = classes
        self.probabilities = probabilities


# Load the fasttext library
try:
    LibUtils.load_library()
except Exception as e:
    global library_status
    library_status = e

class NativeResource:
    def __init__(self, handle):
        self.handle = handle

    @staticmethod
    def close(handle: int) -> None:
        if handle is not None:
            FastTextLibrary.free_fasttext(handle)


# Define the fasttext library functions
FastTextLibrary = {
    'create_fasttext': ctypes.CDLL('fasttext').create_fasttext,
    'load_model': ctypes.CDLL('fasttext').load_model,
    'check_model': ctypes.CDLL('fasttext').check_model,
    'unload_model': ctypes.CDLL('fasttext').unload_model,
    'get_model_type': ctypes.CDLL('fasttext').get_model_type,
    'predict_proba': ctypes.CDLL('fasttext').predict_proba,
    'run_cmd': ctypes.CDLL('fasttext').run_cmd,
    'free_fasttext': ctypes.CDLL('fasttext').free_fasttext
}
