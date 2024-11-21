import io
from typing import List

class IRoleAccessor:
    def load_role(self, rolename: str) -> 'Role' or None:
        # implement this method in your subclass
        pass

    def save_role(self, role: 'Role') -> None:
        # implement this method in your subclass
        pass

    def delete_role(self, rolename: str) -> bool:
        # implement this method in your subclass
        pass

    def list_all_roles(self) -> List[str]:
        # implement this method in your subclass
        pass

    def reset(self) -> None:
        # implement this method in your subclass
        pass


class RoleAccessor(IRoleAccessor):
    # implement the methods of IRoleAccessor here
