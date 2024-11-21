import os
import io
from typing import List, Set

class LocalFileUserAccessor:
    def __init__(self, user_dir_path: str):
        self.user_dir_path = user_dir_path
        self.encoding_buffer_local = threading.local()
        self.str_buffer_local = threading.local()

    def load_user(self, username: str) -> 'User':
        profile_file = os.path.join(self.user_dir_path, f"{username}{IoTDBConstant.PROFILE_SUFFIX}")
        if not os.path.exists(profile_file) or not os.path.isfile(profile_file):
            temp_profile_file = profile_file + ".temp"
            if os.path.exists(temp_profile_file) and os.path.isfile(temp_profile_file):
                try:
                    os.rename(temp_profile_file, profile_file)
                except Exception as e:
                    logger.error("New profile renaming failed: {}", e)
                    return None
        with open(profile_file, 'rb') as f:
            data = io.BytesIO(f.read())
            user = User()
            user.name = self._read_string(data, "utf-8", self.str_buffer_local)
            user.password = self._read_string(data, "utf-8", self.str_buffer_local)
            privilege_num = int.from_bytes(data.read(4), 'big')
            path_privilege_list = []
            for _ in range(privilege_num):
                path_privilege = self._read_path_privilege(data, "utf-8", self.str_buffer_local)
                path_privilege_list.append(path_privilege)
            user.privilege_list = path_privilege_list
            role_num = int.from_bytes(data.read(4), 'big')
            role_list = []
            for _ in range(role_num):
                username = self._read_string(data, "utf-8", self.str_buffer_local)
                role_list.append(username)
            user.role_list = role_list

        try:
            water_mark = data.read(1)[0] != 0
        except EOFError as e:
            water_mark = False
            with open(profile_file, 'r+b') as f:
                f.seek(os.path.getsize(profile_file))
                f.write(int.to_bytes(0, 4, 'big'))
        return user

    def _read_string(self, data: io.BytesIO, encoding: str, buffer_local):
        if not hasattr(buffer_local, "get"):
            buffer_local = threading.local()
        buffer = buffer_local.get("buffer", bytearray())
        buffer_local["buffer"] = buffer
        length = int.from_bytes(data.read(4), 'big')
        data.seek(-4, 1)
        return str.decode(data.read(length).decode(encoding), encoding)

    def _read_path_privilege(self, data: io.BytesIO, encoding: str, buffer_local):
        if not hasattr(buffer_local, "get"):
            buffer_local = threading.local()
        buffer = buffer_local.get("buffer", bytearray())
        buffer_local["buffer"] = buffer
        length = int.from_bytes(data.read(4), 'big')
        data.seek(-4, 1)
        return PathPrivilege(str.decode(data.read(length).decode(encoding), encoding))

    def save_user(self, user: User):
        temp_profile_file = os.path.join(self.user_dir_path, f"{user.name}{IoTDBConstant.PROFILE_SUFFIX}.temp")
        with open(temp_profile_file, 'wb') as f:
            self._write_string(f, "utf-8", buffer_local)
            self._write_string(f, "utf-8", buffer_local)

    def _write_string(self, file: io.FileIO, encoding: str):
        if not hasattr(buffer_local, "get"):
            buffer_local = threading.local()
        buffer = buffer_local.get("buffer", bytearray())
        buffer_local["buffer"] = buffer
        length = len(str.encode(user.name).decode(encoding))
        file.write(int.to_bytes(length, 4, 'big'))
        file.write(str.encode(user.name).encode(encoding))

    def delete_user(self, username: str) -> bool:
        profile_file = os.path.join(self.user_dir_path, f"{username}{IoTDBConstant.PROFILE_SUFFIX}")
        temp_profile_file = os.path.join(self.user_dir_path, f"{username}{IoTDBConstant.PROFILE_SUFFIX}.temp")
        if not os.path.exists(profile_file) and not os.path.exists(temp_profile_file):
            return False
        try:
            os.remove(profile_file)
            os.rename(temp_profile_file, profile_file)
        except Exception as e:
            logger.error("Cannot delete user file of {}: {}", username, e)
            return False
        return True

    def list_all_users(self) -> List[str]:
        user_dir = self.user_dir_path
        names = [name for name in os.listdir(user_dir) if name.endswith(IoTDBConstant.PROFILE_SUFFIX) or name.endswith(".temp")]
        ret_list = []
        set_ = set()
        for name in names:
            set_.add(name.replace(IoTDBConstant.PROFILE_SUFFIX, "").replace(".temp", ""))
        ret_list.extend(list(set_))
        return ret_list

    def reset(self):
        if os.path.exists(self.user_dir_path) and not os.makedirs(self.user_dir_path):
            logger.info("user info dir {} is created", self.user_dir_path)
        else:
            logger.error("user info dir {} can not be created", self.user_dir_path)

class User:
    def __init__(self):
        self.name = ""
        self.password = ""
        self.privilege_list = []
        self.role_list = []

    @property
    def use_water_mark(self) -> bool:
        return False

    @use_water_mark.setter
    def use_water_mark(self, value: bool):
        if not hasattr(self, "_water_mark"):
            self._water_mark = threading.local()
        self._water_mark["value"] = value
