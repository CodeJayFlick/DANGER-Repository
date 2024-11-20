import os
import sys
from tempfile import gettempdir

class TestApplicationUtils:
    def __init__(self):
        pass

    @staticmethod
    def current_repo_directory():
        user_dir = os.environ.get('USER_DIR')
        if not user_dir:
            return None
        repo = ModuleUtilities.find_repo(os.path.join(user_dir, 'Ghidra'))
        return repo

    @staticmethod
    def get_installation_directory():
        repo = TestApplicationUtils.current_repo_directory()
        if repo is not None:
            return repo
        current_dir = os.environ.get('USER_DIR')
        msg.debug(f"User dir: {current_dir}")

        jar_file_path = sys._getframe().f_code.co_filename
        parts = os.path.normpath(jar_file_path).split(os.sep)
        install_dir_index = len(parts) - 5

        path = os.sep.join(parts[:install_dir_index])
        return os.path.abspath(path)

    @staticmethod
    def get_unique_temp_folder():
        repos_container = TestApplicationUtils.get_installation_directory()
        if not repos_container:
            tmp_dir = gettempdir()
            temp_name = tmp_dir.split(os.sep)[-1]
            name = f"{repos_container.name}{temp_name}"
            return os.path.join(tmp_dir, name)
