import os
import logging
from pathlib import Path
import shutil
import tempfile

class LibUtils:
    logger = logging.getLogger(__name__)

    LIB_NAME = "djl_trt"

    def __init__(self):
        pass

    @staticmethod
    def load_library():
        if not os.environ.get("os.name").startswith("Linux"):
            raise UnsupportedOperationException("TensorRT only supports Linux.")

        lib_name = LibUtils.copy_jni_library_from_classpath()
        logger.debug(f"Loading TensorRT JNI library from: {lib_name}")
        try:
            _ = __import__(lib_name)
        except ImportError as e:
            raise ImportError(f"Failed to load library: {e}")

    @staticmethod
    def copy_jni_library_from_classpath():
        name = f"{LibUtils.LIB_NAME}"
        platform = Platform.from_system()
        classifier = platform.get_classifier()

        try:
            with LibUtils.class_resourceAsStream("/jnilib/tensorrt.properties") as stream:
                prop = Properties().load(stream)
        except IOError as e:
            raise IOError(f"Cannot find TensorRT property file: {e}")

        version = prop["version"]
        cache_dir = Path(Utils.get_engine_cache_dir("tensorrt"))
        dir_path = cache_dir / f"{version}-{classifier}"
        lib_path = dir_path / name

        if lib_path.exists():
            return str(lib_path)

        tmp_path = None
        try:
            with LibUtils.class_resourceAsStream(f"/jnilib/{classifier}/{name}") as stream:
                if not stream:
                    raise IOError(f"TensorRT library not found: {lib_path}")
                Files.create_dirs(dir_path)
                tmp_path = tempfile.mktempdir()
                shutil.copyfileobj(stream, open(tmp_path, "wb"))
                shutil.move(tmp_path, str(lib_path))
            return str(lib_path)
        except IOError as e:
            raise IOError(f"Cannot copy jni files: {e}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                shutil.rmtree(tmp_path)

    @staticmethod
    def class_resourceAsStream(path):
        with LibUtils.__class__.getResourceAsStream(path) as stream:
            return stream

# Usage example
LibUtils.load_library()
