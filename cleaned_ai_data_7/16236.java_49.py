import os
import logging
from pathlib import Path
import shutil
try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

class LibUtils:
    _logger = logging.getLogger(__name__)

    LIB_NAME = "sentencepiece_ native"

    def __init__(self):
        pass

    @staticmethod
    def load_library():
        if os.name.startswith("nt"):
            raise NotImplementedError("Windows is not supported.")

        lib_name = copy_jni_library_from_classpath()
        _logger.debug(f"Loading sentencepiece library from: {lib_name}")
        try:
            import ctypes.util.find_library
            return ctypes.util.find_library(lib_name)
        except Exception as e:
            print(f"Failed to load the library. Error message: {str(e)}")

    @staticmethod
    def copy_jni_library_from_classpath():
        name = f"{LibUtils.LIB_NAME}"
        native_dir = Path(__file__).parent / "native"
        try:
            with open(os.path.join(native_dir, "sentencepiece.properties"), 'r') as stream:
                prop = Properties()
                prop.load(stream)
        except Exception as e:
            print(f"Failed to read files. Error message: {str(e)}")
            return None

        version = prop.get("version", "")
        path = native_dir / version / name
        if os.path.exists(path):
            return str(path)

        tmp_path = Path(__file__).parent / "tmp"
        lib_path = f"/native/lib/{os.name.split('.')[1]}/{name}"
        _logger.info(f"Extracting {lib_path} to cache ...")
        try:
            with urlopen(lib_path) as stream:
                if not stream:
                    raise Exception(f"SentencePiece library not found: {lib_path}")
                os.makedirs(native_dir / version, exist_ok=True)
                tmp = Path(__file__).parent / "tmp"
                shutil.copy2(stream, tmp)
                shutil.move(tmp, path)
            return str(path)
        except Exception as e:
            print(f"Cannot copy jni files. Error message: {str(e)}")
            return None
        finally:
            if os.path.exists(tmp_path):
                try:
                    shutil.rmtree(str(tmp_path))
                except Exception as e:
                    _logger.error(f"Failed to delete temporary file. Error message: {str(e)}")

if __name__ == "__main__":
    LibUtils.load_library()
