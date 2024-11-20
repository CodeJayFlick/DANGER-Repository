import os
from abc import ABCMeta, abstractmethod


class ConvertFileSystemException(Exception):
    pass


def get_dir(path: str) -> tuple:
    if path is None:
        raise ConvertFileSystemException("Must specify a project (*.rep) or server repositories directory")
    dir = os.path.normpath(os.path.abspath(path))
    if not os.path.isdir(dir):
        raise ConvertFileSystemException(f"Invalid project or repositories directory specified: {dir}")
    return dir


def convert_repositories(dir: str, msg_listener=None) -> None:
    try:
        file = os.path.join(dir, "~admin")
        if not os.path.exists(file) and not os.path.isdir(file):
            raise ConvertFileSystemException(f"Invalid repositories directory specified (~admin not found): {dir}")
        file = os.path.join(dir, "users")
        if not os.path.isfile(file):
            raise ConvertFileSystemException(f"Invalid repositories directory specified (users not found): {dir}")
        file = os.path.join(dir, "server.log")
        if not os.path.isfile(file):
            raise ConvertFileSystemException(f"Invalid repositories directory specified (server.log not found): {dir}")

        repo_dirs = [os.path.join(dir, f) for f in os.listdir(dir) if os.path.isdir(os.path.join(dir, f))]
        msg_listener.println(f"Converting {len(repo_dirs)} repositories...")
        for repo_dir in repo_dirs:
            convert_repo(repo_dir, msg_listener)
    except ConvertFileSystemException as e:
        print(e)


def convert_repo(repo_dir: str, msg_listener=None) -> None:
    try:
        fs = LocalFileSystem.get_local_file_system(os.path.abspath(repo_dir), False, True, False, False)
        if isinstance(fs, MangledLocalFileSystem):
            mfs = fs
            msg_listener.println(f"Converting repository directory: {repo_dir}")
            mfs.convert_to_indexed_local_file_system()
        elif isinstance(fs, IndexedLocalFileSystem) and (IndexedLocalFileSystem).get_latest_index_version() < 1:
            msg_listener.println(
                f"Rebuilding Index for repository directory ({fs.get_item_count()} files): {repo_dir}"
            )
            fs.dispose()
            IndexedV1LocalFileSystem.rebuild(repo_dir)
        else:
            msg_listener.println(f"Repository directory has previously been converted: {repo_dir}")
    except (IOException, ConvertFileSystemException) as e:
        if isinstance(e, ConvertFileSystemException):
            raise e
        print(f"Error converting repository directory ({repo_dir}): {e}")


def convert_project(dir: str, msg_listener=None) -> None:
    try:
        project_properties_file = os.path.join(dir, "project.prp")
        if not os.path.isfile(project_properties_file):
            raise ConvertFileSystemException(
                f"Invalid project directory specified (project.prp not found): {dir}"
            )
        data_dir = os.path.join(dir, "data")
        if not os.path.isdir(data_dir):
            data_dir = os.path.join(dir, "idata")  # allow index upgrade
        if not os.path.isdir(data_dir):
            raise ConvertFileSystemException(
                f"Invalid project directory specified (project data not found): {dir}"
            )

        convert_project_dir(data_dir, "data", msg_listener)

        versioned_dir = os.path.join(dir, "versioned")
        if os.path.exists(versioned_dir) and os.path.isdir(versioned_dir):
            convert_project_dir(versioned_dir, "versioned data", msg_listener)
        user_dir = os.path.join(dir, "user")
        if os.path.exists(user_dir) and os.path.isdir(user_dir):
            convert_project_dir(user_dir, "user data", msg_listener)

    except ConvertFileSystemException as e:
        print(f"Error converting project directory ({dir}): {e}")


class MessageListener(metaclass=ABCMeta):
    @abstractmethod
    def println(self, string: str) -> None:
        pass


if __name__ == "__main__":
    msg_listener = lambda s: print(s)
    convert_repositories(get_dir("path_to_your_project_or_server"), msg_listener)

