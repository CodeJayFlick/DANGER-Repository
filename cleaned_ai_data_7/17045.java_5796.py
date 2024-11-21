import logging
from collections import defaultdict

class TriggerClassLoaderManager:
    _logger = logging.getLogger(__name__)
    _lib_root = IoTDBDescriptor.getInstance().getConfig().get_trigger_dir()

    def __init__(self):
        self._classNameToClassLoaderUsagePairMap = defaultdict(dict)

    def register(self, className) -> 'TriggerClassLoader':
        if not self._classNameToClassLoaderUsagePairMap[className]:
            try:
                class_loader = TriggerClassLoader(_lib_root)
                self._classNameToClassLoaderUsagePairMap[className][0] = (class_loader, 0)
                _logger.info(f"A new trigger classloader was constructed for managing trigger class {className}.")
            except Exception as e:
                raise TriggerManagementException(
                    f"Failed to construct a new trigger classloader for managing trigger class {className}",
                    e
                )
        self._classNameToClassLoaderUsagePairMap[className][0][1] += 1
        return self._classNameToClassLoaderUsagePairMap[className][0][0]

    def deregister(self, className):
        if not self._classNameToClassLoaderUsagePairMap[className]:
            raise Exception(f"Trigger class {className} is not registered.")
        usage = self._classNameToClassLoaderUsagePairMap[className]
        usage[1] -= 1
        if usage[1] == 0:
            try:
                _logger.info(f"A trigger classloader for managing trigger class {className} was removed.")
                usage[0].close()
            except Exception as e:
                _logger.warn(f"Failed to close a trigger classloader ({className}).", e)

    @staticmethod
    def get_instance():
        return TriggerClassLoaderManager._instance

TriggerClassLoaderManager._instance = None


class TriggerManagementException(Exception):
    pass
