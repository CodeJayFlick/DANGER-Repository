import io

class RemoteRepositoryServerHandle:
    def anonymous_access_allowed(self) -> bool:
        pass  # To be implemented by subclass

    def is_read_only(self) -> bool:
        pass  # To be implemented by subclass

    def create_repository(self, name: str) -> 'RemoteRepositoryServerHandle':
        pass  # To be implemented by subclass

    def get_repository(self, name: str) -> 'RemoteRepositoryServerHandle':
        pass  # To be implemented by subclass

    def delete_repository(self, name: str):
        pass  # To be implemented by subclass

    def get_repository_names(self) -> list:
        pass  # To be implemented by subclass

    def get_user(self) -> str:
        pass  # To be implemented by subclass

    def get_all_users(self) -> list:
        pass  # To be implemented by subclass

    def can_set_password(self) -> bool:
        pass  # To be implemented by subclass

    def get_password_expiration(self) -> int:
        pass  # To be implemented by subclass

    def set_password(self, salted_sha256_password_hash: bytes):
        pass  # To be implemented by subclass

    def connected(self):
        pass  # To be implemented by subclass
