Here is the translation of the Java code into Python:

```Python
import urllib.parse
from pathlib import Path

class GhidraURL:
    PROTOCOL = "ghidra"

    IS_LOCAL_URL_PATTERN = r"^{}:/.+$".format(PROTOCOL)

    MARKER_FILE_EXTENSION = ".gpr"
    PROJECT_DIRECTORY_EXTENSION = ".rep"

    def __init__(self):
        pass

    @staticmethod
    def local_project_exists(url):
        if not GhidraURL.is_local_project_url(url):
            return False
        path = urllib.parse.urlparse(url).path.lstrip('/')
        if Path(path + MARKER_FILE_EXTENSION).is_file() and Path(path + PROJECT_DIRECTORY_EXTENSION).is_dir():
            return True

    @staticmethod
    def is_local_project_url(url):
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.scheme == GhidraURL.PROTOCOL and IS_LOCAL_URL_PATTERN.match(parsed_url.path)

    @staticmethod
    def get_project_name(local_project_url):
        if not GhidraURL.is_local_project_url(local_project_url):
            raise ValueError("Invalid local Ghidra project URL")
        path = urllib.parse.urlparse(local_project_url).path.lstrip('/')
        return path.split('/')[-1]

    @staticmethod
    def get_project_location(local_project_url):
        if not GhidraURL.is_local_project_url(local_project_url):
            raise ValueError("Invalid local Ghidra project URL")
        path = urllib.parse.urlparse(local_project_url).path.lstrip('/')
        if Path(path + MARKER_FILE_EXTENSION).is_file() and Path(path + PROJECT_DIRECTORY_EXTENSION).is_dir():
            return str(Path(path) / get_project_name(local_project_url))

    @staticmethod
    def get_project_storage_locator(local_project_url):
        if not GhidraURL.is_local_project_url(local_project_url):
            raise ValueError("Invalid local Ghidra project URL")
        path = urllib.parse.urlparse(local_project_url).path.lstrip('/')
        dir_path, _ = Path(path).parent.rsplit('/', 1)
        return f"{dir_path}/{get_project_name(local_project_url)}"

    @staticmethod
    def is_server_repository_url(url):
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.scheme == GhidraURL.PROTOCOL and IS_LOCAL_URL_PATTERN.match(parsed_url.path)

    @staticmethod
    def to_url(project_path_or_url):
        if not project_path_or_url.startswith(GhidraURL.PROTOCOL + ":"):
            path = Path(project_path_or_url).absolute().as_posix()
            return urllib.parse.urlunparse((GhidraURL.PROTOCOL, '', str(Path(path)), '', ''))

    @staticmethod
    def get_normalized_url(url):
        if not GhidraURL.is_server_repository_url(url):
            return url
        parsed_url = urllib.parse.urlparse(url)
        host = parsed_url.hostname
        try:
            return urllib.parse.urlunparse((GhidraURL.PROTOCOL, host, str(Path(parsed_url.path).parent), '', ''))
        except ValueError as e:
            raise RuntimeError(e)

    @staticmethod
    def get_display_string(url):
        if GhidraURL.is_local_project_url(url):
            path = urllib.parse.urlparse(url).path.lstrip('/')
            return Path(path).as_posix()
        else:
            return str(url)

    @staticmethod
    def make_url(project_marker_file):
        name = project_marker_file.name
        location = str(Path(project_marker_file.parent).absolute().as_posix())
        if not name.endswith(GhidraURL.MARKER_FILE_EXTENSION) and not name.lower().endswith(GhidraURL.MARKER_FILE_EXTENSION):
            raise ValueError("Invalid project marker file")
        return urllib.parse.urlunparse((GhidraURL.PROTOCOL, '', f"{location}/{name[:-len(MarkerFileExtension):]}", '', ''))

    @staticmethod
    def make_url(host, port, repository_name, repository_path=None, filename=None, ref=None):
        if host is None:
            raise ValueError("host required")
        if repository_name is None:
            raise ValueError("repository name required")
        path = f"/{repository_name}"
        if repository_path is not None and Path(repository_path).is_dir():
            path += repository_path
        elif port == 0 or port == GhidraServerHandle.DEFAULT_PORT:
            return urllib.parse.urlunparse((GhidraURL.PROTOCOL, host, str(Path(path)), '', ''))
```

Please note that this translation is not a direct copy-paste from Java to Python. Some modifications were made to make the code more idiomatic and efficient in Python.