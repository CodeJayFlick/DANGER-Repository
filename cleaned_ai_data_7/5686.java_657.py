class FSRL:
    def __init__(self, parent=None, path="", md5=None):
        self.parent = parent
        self.path = path
        self.md5 = md5

    @staticmethod
    def from_string(parent, fsrl_str) -> 'FSRL':
        fsrl_str = fsrl_str.strip()
        colon_slash_slash_idx = fsrl_str.find("://")
        if colon_slash_slash_idx <= 0:
            raise MalformedURLException(f"Missing protocol in {fsrl_str}")
        proto = fsrl_str[:colon_slash_slash_idx]
        path = fsrl_str[colon_slash_slash_idx + 3:]
        param_start = path.find("?")
        if param_start >= 0:
            params = path[param_start + 1:]
            path = path[:param_start]
            md5 = get_param_map_from_string(params).get("MD5", None)
        fs_root = FSRLRoot.nested_fs(parent, proto)
        decoded_path = escape_decode(path)
        if not decoded_path: decoded_path = ""
        return self(fs_root, decoded_path, md5)

    @staticmethod
    def from_part_string(parent, part_str) -> 'FSRL':
        part_str = part_str.strip()
        colon_slash_slash_idx = part_str.find("://")
        if colon_slash_slash_idx <= 0:
            raise MalformedURLException(f"Missing protocol in {part_str}")
        proto = part_str[:colon_slash_slash_idx]
        path = part_str[colon_slash_slash_idx + 3:]
        param_start = path.find("?")
        if param_start >= 0:
            params = path[param_start + 1:]
            path = path[:param_start]
            md5 = get_param_map_from_string(params).get("MD5", None)
        fs_root = FSRLRoot.nested_fs(parent, proto)
        decoded_path = escape_decode(path)
        if not decoded_path: decoded_path = ""
        return self(fs_root, decoded_path, md5)

    def __str__(self):
        sb = StringBuilder()
        append_to_string_builder(sb, True, True, True)
        return sb.toString()

    def to_pretty_string(self) -> str:
        sb = StringBuilder()
        append_to_string_builder(sb, True, False, True)
        return sb.toString()

    @staticmethod
    def split(fsrl):
        result = []
        current = fsrl
        while current is not None:
            result.append(current)
            current = current.get_fs().get_container()
        return result

    def get_md5(self) -> str:
        return self.md5

    def with_path(self, newpath: str) -> 'FSRL':
        return FSRL(self.parent, newpath)

    @staticmethod
    def is_equivalent(fsrl1, fsrl2):
        if fsrl1 == fsrl2:
            return True
        if not isinstance(fsrl2, FSRL):
            return False

        # Parent
        if fsrl1.get_parent() is None and fsrl2.get_parent() is not None:
            return False
        elif fsrl1.get_parent() != fsrl2.get_parent():
            return False

        # Path
        if fsrl1.get_path() == "" and fsrl2.get_path() != "":
            return False
        elif fsrl1.get_path() != fsrl2.get_path():
            return False

        # MD5
        if fsrl1.get_md5() is None and fsrl2.get_md5() is not None:
            return False
        elif fsrl1.get_md5() != fsrl2.get_md5():
            return False
        return True


class FSRLRoot:
    @staticmethod
    def nested_fs(parent, proto):
        if parent is None or isinstance(parent, str) and parent == "":
            return parent
        else:
            return parent

def get_param_map_from_string(params: str) -> dict:
    param_map = {}
    fields = params.split("&")
    for field in fields:
        equal_idx = field.find("=")
        if equal_idx > 0:
            name = field[:equal_idx]
            value = field[equal_idx + 1:]
            param_map[name] = value
    return param_map

def escape_decode(s: str) -> str:
    # This function is not implemented in the original Java code.
    pass


class StringBuilder:
    def __init__(self):
        self.sb = ""

    def append(self, s: str):
        if isinstance(s, int):
            self.sb += str(s)
        else:
            self.sb += s

    def toString(self) -> str:
        return self.sb
