Here is the translation of the Java code into Python:

```Python
import os
import logging
from concurrent.futures import ThreadPoolExecutor

class UDFClassLoaderManager:
    def __init__(self):
        self.lib_root = IoTDBDescriptor().get_config().get_udf_dir()
        logger.info("UDF lib root: {}".format(self.lib_root))
        self.query_id_to_udf_classloader_map = {}
        self.active_classloader = None

    @property
    def active_classloader(self):
        return self._active_classloader

    @active_classloader.setter
    def active_classloader(self, value):
        self._active_classloader = value

    def initialize_udf_query(self, query_id):
        if not self.active_classloader:
            raise Exception("UDFClassLoader is not initialized")
        self.query_id_to_udf_classloader_map[query_id] = self.active_classloader
        self.active_classloader.acquire()

    def finalize_udf_query(self, query_id):
        classloader = self.query_id_to_udf_classloader_map.pop(query_id)
        try:
            classloader.release()
        except Exception as e:
            logger.warning("Failed to close UDFClassLoader (queryId: {}), because {}".format(query_id, str(e)))

    def update_get_active_classloader(self):
        deprecated_classloader = self.active_classloader
        self.active_classloader = UDFClassLoader(self.lib_root)
        deprecated_classloader.mark_as_deprecated()
        return self.active_classloader

    @property
    def active_classloader_(self):
        return self._active_classloader_

    @active_classloader_.setter
    def _set_active_classloader_(self, value):
        self._active_classloader_ = value

class UDFClassLoader:
    def __init__(self, lib_root):
        self.lib_root = lib_root

    def acquire(self):
        pass  # implement this method in the actual class

    def release(self):
        pass  # implement this method in the actual class

    def mark_as_deprecated(self):
        pass  # implement this method in the actual class


class IoTDBDescriptor:
    @staticmethod
    def get_config():
        return {}

    @staticmethod
    def get_udf_dir():
        return "path_to_your_udf_directory"


def make_dir_if_necessary(lib_root):
    file = os.path.join(lib_root)
    if not os.path.exists(file) or not os.path.isdir(file):
        try:
            os.makedirs(file, exist_ok=True)
        except Exception as e:
            raise


class StartupException(Exception):
    pass

if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    udf_classloader_manager = UDFClassLoaderManager()
    make_dir_if_necessary(udf_classloader_manager.lib_root)
    try:
        udf_classloader_manager.active_classloader = UDFClassLoader(udf_classloader_manager.lib_root)
    except Exception as e:
        raise StartupException("Failed to start", str(e))

    # implement the rest of your code here
```

Please note that this is a direct translation from Java, and some parts might not work correctly in Python. You would need to fill in the implementation details for methods like `acquire`, `release` and `mark_as_deprecated`.