Here is the translation of the Java code to Python:
```
import logging

class BasicAuthorizer:
    def __init__(self, userManager: 'IUserManager', roleManager: 'IRoleManager'):
        self.user_manager = userManager
        self.role_manager = roleManager
        self.init()

    def init(self):
        self.user_manager.reset()
        self.role_manager.reset()
        logging.info("Initialization of Authorizer completes")

    @staticmethod
    def get_instance() -> 'IAuthorizer':
        if not hasattr(InstanceHolder, "instance"):
            raise AuthException("Authorizer uninitialized")
        return InstanceHolder.instance

    class InstanceHolder:
        instance = None

        @classmethod
        def __init__(cls):
            try:
                provider_class = Class.forName(IoTDBDescriptor.getInstance().getConfig().get_authorizer_provider())
                logging.info(f"Authorizer provider class: {IoTDBDescriptor.getInstance().getConfig().get_authorizer_provider()}")
                InstanceHolder.instance = provider_class.getDeclaredConstructor().__invoke__()
            except Exception as e:
                InstanceHolder.instance = None
                raise IllegalStateException("Authorizer could not be initialized!", e)

    def is_admin(self, username: str) -> bool:
        # abstract method implementation
        pass

    def login(self, username: str, password: str) -> bool:
        user = self.user_manager.get_user(username)
        return user and password and user.password == AuthUtils.encrypt_password(password)

    def create_user(self, username: str, password: str):
        if not self.user_manager.create_user(username, password):
            raise AuthException(f"User {username} already exists")

    def delete_user(self, username: str):
        if self.is_admin(username):
            raise AuthException("Default administrator cannot be deleted")
        if not self.user_manager.delete_user(username):
            raise AuthException(f"User {username} does not exist")

    def grant_privilege_to_user(self, username: str, path: str, privilege_id: int) -> None:
        new_path = path
        if self.is_admin(username):
            raise AuthException("Invalid operation, administrator already has all privileges")
        if not PrivilegeType.is_path_relevant(privilege_id):
            new_path = IoTDBConstant.PATH_ROOT
        if not self.user_manager.grant_privilege_to_user(username, new_path, privilege_id):
            raise AuthException(f"User {username} already has {PrivilegeType.values()[privilege_id]} on {path}")

    def revoke_privilege_from_user(self, username: str, path: str, privilege_id: int) -> None:
        if self.is_admin(username):
            raise AuthException("Invalid operation, administrator must have all privileges")
        p = path
        if not PrivilegeType.is_path_relevant(privilege_id):
            p = IoTDBConstant.PATH_ROOT
        if not self.user_manager.revoke_privilege_from_user(username, p, privilege_id):
            raise AuthException(f"User {username} does not have {PrivilegeType.values()[privilege_id]} on {path}")

    def create_role(self, role_name: str) -> None:
        if not self.role_manager.create_role(role_name):
            raise AuthException(f"Role {role_name} already exists")

    def delete_role(self, role_name: str) -> None:
        success = self.role_manager.delete_role(role_name)
        if not success:
            raise AuthException(f"Role {role_name} does not exist")
        # proceed to revoke the role in all users
        for user in self.user_manager.list_all_users():
            try:
                self.user_manager.revoke_role_from_user(role_name, user)
            except Exception as e:
                logging.warn(f"Error encountered when revoking a role {role_name} from user {user}, because {e}")

    def grant_privilege_to_role(self, role_name: str, path: str, privilege_id: int) -> None:
        p = path
        if not PrivilegeType.is_path_relevant(privilege_id):
            p = IoTDBConstant.PATH_ROOT
        if not self.role_manager.grant_privilege_to_role(role_name, p, privilege_id):
            raise AuthException(f"Role {role_name} already has {PrivilegeType.values()[privilege_id]} on {path}")

    def revoke_privilege_from_role(self, role_name: str, path: str, privilege_id: int) -> None:
        p = path
        if not PrivilegeType.is_path_relevant(privilege_id):
            p = IoTDBConstant.PATH_ROOT
        if not self.role_manager.revoke_privilege_from_role(role_name, p, privilege_id):
            raise AuthException(f"Role {role_name} does not have {PrivilegeType.values()[privilege_id]} on {path}")

    def grant_role_to_user(self, role_name: str, username: str) -> None:
        role = self.role_manager.get_role(role_name)
        if role is None:
            raise AuthException(f"Role {role_name} does not exist")
        # the role may be deleted before it's granted to the user, so a double check is necessary
        success = self.user_manager.grant_role_to_user(role_name, username)
        if success:
            role = self.role_manager.get_role(role_name)
            if role is None:
                raise AuthException(f"Role {role_name} does not exist")
        else:
            raise AuthException(f"User {username} already has role {role_name}")

    def revoke_role_from_user(self, role_name: str, username: str) -> None:
        role = self.role_manager.get_role(role_name)
        if role is None:
            raise AuthException(f"Role {role_name} does not exist")
        if not self.user_manager.revoke_role_from_user(role_name, username):
            raise AuthException(f"User {username} does not have role {role_name}")

    def get_privileges(self, username: str, path: str) -> set:
        if self.is_admin(username):
            return ADMIN_PRIVILEGES
        user = self.user_manager.get_user(username)
        if user is None:
            raise AuthException(f"User {username} does not exist")
        # get privileges of the user
        privileges = user.privileges(path)
        # merge the privileges of the roles of the user
        for role_name in user.role_list():
            role = self.role_manager.get_role(role_name)
            if role is not None:
                privileges.update(role.privileges(path))
        return privileges

    def update_user_password(self, username: str, new_password: str) -> None:
        if not self.user_manager.update_user_password(username, new_password):
            raise AuthException("password " + new_password + " is illegal")

    def check_user_privileges(self, username: str, path: str, privilege_id: int) -> bool:
        if self.is_admin(username):
            return True
        user = self.user_manager.get_user(username)
        if user is None:
            raise AuthException(f"User {username} does not exist")
        # get privileges of the user
        if user.check_privilege(path, privilege_id):
            return True
        # merge the privileges of the roles of the user
        for role_name in user.role_list():
            role = self.role_manager.get_role(role_name)
            if role is not None:
                if role.check_privilege(path, privilege_id):
                    return True
        return False

    def reset(self) -> None:
        self.init()

    def start(self) -> None:
        try:
            self.init()
        except AuthException as e:
            raise StartupException(e)

    def stop(self) -> None:
        pass

    def get_id(self) -> ServiceType:
        return ServiceType.AUTHORIZATION_SERVICE

    def list_all_users(self) -> List[str]:
        return self.user_manager.list_all_users()

    def list_all_roles(self) -> List[str]:
        return self.role_manager.list_all_roles()

    def get_role(self, role_name: str) -> Role:
        return self.role_manager.get_role(role_name)

    def get_user(self, username: str) -> User:
        return self.user_manager.get_user(username)

    def is_user_use_watermark(self, username: str) -> bool:
        return self.user_manager.is_user_use_watermark(username)
```
Note that I've used the `logging` module to log messages instead of using a custom logging mechanism. Also, I've assumed that the `AuthException`, `IUserManager`, and `IRoleManager` classes are defined elsewhere in your codebase.