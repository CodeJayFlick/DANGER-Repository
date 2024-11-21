Here is the translation of the Java code into equivalent Python:

```Python
import os
from typing import List, Tuple
import logging

class Utils:
    def __init__(self):
        pass

    @staticmethod
    def index_of(array: list, value) -> int:
        if array:
            for i in range(len(array)):
                if value == array[i]:
                    return i
        return -1

    @staticmethod
    def contains(array: list, value) -> bool:
        return Utils.index_of(array, value) >= 0

    @staticmethod
    def pad(sb: str, c: str, count: int):
        for _ in range(count):
            sb += c

    @staticmethod
    def delete_quietly(dir_path: str):
        try:
            for path in os.listdir(dir_path):
                full_path = os.path.join(dir_path, path)
                if os.path.isfile(full_path):
                    os.remove(full_path)
                elif os.path.isdir(full_path):
                    Utils.delete_quietly(full_path)
        except Exception as e:
            logging.error(f"Error deleting directory: {e}")

    @staticmethod
    def move_quietly(source_path: str, target_path: str) -> None:
        try:
            if not os.path.exists(target_path):
                os.rename(source_path, target_path)
            else:
                raise Exception("Target file already exists")
        except Exception as e:
            logging.error(f"Error moving file: {e}")

    @staticmethod
    def to_string(is: bytes) -> str:
        return is.decode('utf-8')

    @staticmethod
    def to_byte_array(is: bytes) -> bytearray:
        ba = bytearray()
        while True:
            chunk = is.read(81920)
            if not chunk:
                break
            ba.extend(chunk)
        return ba

    @staticmethod
    def read_lines(file_path: str, trim=False) -> List[str]:
        try:
            with open(file_path, 'r') as f:
                lines = []
                for line in f.readlines():
                    if trim and not line.strip():
                        continue
                    lines.append(line.decode('utf-8').strip())
                return lines
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            return []

    @staticmethod
    def to_float_array(numbers: List[float]) -> list:
        return [n for n in numbers]

    @staticmethod
    def get_current_epoch(model_dir_path: str, model_name: str) -> int:
        try:
            pattern = r'{}-(\d{4}).params'.format(model_name)
            checkpoints = []
            for root, dirs, files in os.walk(model_dir_path):
                for file in files:
                    if re.match(pattern, file):
                        checkpoint_number = int(re.search(pattern, file).group(1))
                        checkpoints.append(checkpoint_number)
            return max(checkpoints) if checkpoints else -1
        except Exception as e:
            logging.error(f"Error getting current epoch: {e}")
            return -1

    @staticmethod
    def check_parameter_values(parameters: List[Tuple[str, float]], logger):
        for name, value in parameters:
            logger.debug('Checking parameter {}: {}'.format(name, value))
            if not isinstance(value, (int, float)):
                raise ValueError(f"Invalid type for {name}: {type(value)}")

    @staticmethod
    def get_engine_cache_dir(engine: str) -> str:
        cache_dir = os.environ.get("ENGINE_CACHE_DIR")
        if not cache_dir or not cache_dir.strip():
            return os.path.join(os.getcwd(), "cache", engine)
        else:
            return os.path.join(cache_dir, engine)

    @staticmethod
    def get_cache_dir() -> str:
        cache_dir = os.environ.get("DJL_CACHE_DIR")
        if not cache_dir or not cache_dir.strip():
            user_home = os.path.expanduser('~')
            dir_path = os.path.join(user_home, ".djl.ai")
            return dir_path
        else:
            return cache_dir

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an equivalent implementation in Python.