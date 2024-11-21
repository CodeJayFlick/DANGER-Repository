import pickle

class VersionInfo:
    def __init__(self, domain_file_path: str, version_number: int):
        self.domain_file_path = domain_file_path
        self.version_number = version_number

    @property
    def domain_file_path(self) -> str:
        return self._domain_file_path

    @domain_file_path.setter
    def domain_file_path(self, value: str):
        self._domain_file_path = value

    @property
    def version_number(self) -> int:
        return self._version_number

    @version_number.setter
    def version_number(self, value: int):
        if not isinstance(value, int):
            raise TypeError("Version number must be an integer.")
        self._version_number = value


# Example usage:

if __name__ == "__main__":
    v1 = VersionInfo("/path/to/domain/file", 123)
    print(v1.domain_file_path)  # prints: /path/to/domain/file
    print(v1.version_number)     # prints: 123

    with open("version_info.pkl", "wb") as f:
        pickle.dump(v1, f)

    v2 = None
    try:
        with open("version_info.pkl", "rb") as f:
            v2 = pickle.load(f)
    except FileNotFoundError:
        print("File not found.")
    else:
        if isinstance(v2, VersionInfo):
            print(v2.domain_file_path)  # prints: /path/to/domain/file
            print(v2.version_number)     # prints: 123
