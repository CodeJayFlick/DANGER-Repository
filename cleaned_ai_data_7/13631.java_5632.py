import os
from typing import List, Set, Dict, Tuple

class JavaFinder:
    class Platform(Enum):
        WINDOWS = 1
        MACOS = 2
        LINUX = 3

    def __init__(self):
        self._current_platform = None

    @property
    def current_platform(self) -> 'Platform':
        if not self._current_platform:
            os_name = os.environ.get('os.name')
            if os_name and (os_name.lower().startswith('win') or os_name.lower().startswith('windows')):
                self._current_platform = JavaFinder.Platform.WINDOWS
            elif os_name and os_name.lower().startswith('mac'):
                self._current_platform = JavaFinder.Platform.MACOS
        return self._current_platform

    @staticmethod
    def create() -> 'JavaFinder':
        if not hasattr(JavaFinder, '_java_finder_instance'):
            JavaFinder._java_finder_instance = None
            platform = JavaFinder.current_platform
            if platform == JavaFinder.Platform.WINDOWS:
                JavaFinder._java_finder_instance = WindowsJavaFinder()
            elif platform == JavaFinder.Platform.MACOS:
                JavaFinder._java_finder_instance = MacJavaFinder()
            else:  # Linux or unknown
                JavaFinder._java_finder_instance = LinuxJavaFinder()

        return JavaFinder._java_finder_instance

    def find_supported_java_home_from_installations(self, java_config: 'JavaConfig', 
                                                      java_filter: 'JavaFilter') -> List['File']:
        potential_java_home_set = set()
        for root_install_dir in self.get_java_root_install_dirs():
            if os.path.isdir(root_install_dir):
                for dir in os.listdir(root_install_dir):
                    path = os.path.join(root_install_dir, dir)
                    if os.path.isdir(path):
                        java_home_subdir_path = self.get_java_home_subdir_path()
                        potential_java_home_set.add(os.path.join(path, java_home_subdir_path))
        supported_java_homes = []
        for potential_java_home in potential_java_home_set:
            try:
                version = java_config.get_java_version(potential_java_home, java_filter)
                if java_config.is_java_version_supported(version):
                    supported_java_homes.append(potential_java_home)
            except (ParseException, IOException) as e:
                pass
        return sorted(supported_java_homes)

    def find_supported_java_home_from_current_java_home(self, 
                                                         java_config: 'JavaConfig', 
                                                         java_filter: 'JavaFilter') -> Tuple['File']:
        potential_java_home_set = set()
        if (java_home := os.environ.get('java.home')) and java_home:
            dir_path = os.path.join(java_home)
            for file in [os.path.join(dir_path, 'jre'), os.path.join(dir_path, 'jdk')]:
                if os.path.isdir(file):
                    potential_java_home_set.add(os.path.dirname(file))
        return tuple(potential_java_home_set)

    def get_java_root_install_dirs(self) -> List['File']:
        raise NotImplementedError

    def get_java_home_subdir_path(self) -> str:
        raise NotImplementedError

    def get_jre_home_from_java_home(self, java_home_dir: 'File') -> Tuple['File']:
        raise NotImplementedError

    def get_jdk_home_from_java_home(self, java_home_dir: 'File') -> Tuple['File']:
        raise NotImplementedError
