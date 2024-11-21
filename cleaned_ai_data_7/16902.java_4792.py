import os

class LocalFileAuthorizer:
    def __init__(self):
        config = IoTDBConfig()
        self.user_manager = LocalFileUserManager(os.path.join(config.system_dir, "users"))
        self.role_manager = LocalFileRoleManager(os.path.join(config.system_dir, "roles"))

    @property
    def is_admin(self, username: str) -> bool:
        return config.admin_name == username

class IoTDBConfig:
    system_dir = ""

class LocalFileUserManager:
    def __init__(self, user_dir):
        self.user_dir = user_dir

class LocalFileRoleManager:
    def __init__(self, role_dir):
        self.role_dir = role_dir
