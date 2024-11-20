class BasicRoleManager:
    def __init__(self, accessor):
        self.role_map = {}
        self.accessor = accessor
        self.lock = {}

    def get_role(self, rolename):
        if rolename in self.role_map:
            return self.role_map[rolename]
        
        try:
            role = self.accessor.load_role(rolename)
            if role is not None:
                self.role_map[rolename] = role
            return role
        except Exception as e:
            raise AuthException(e)

    def create_role(self, rolename):
        if rolename in self.role_map:
            return False
        
        try:
            role = Role(rolename)
            self.accessor.save_role(role)
            self.role_map[rolename] = role
            return True
        except Exception as e:
            raise AuthException(e)

    def delete_role(self, rolename):
        if rolename not in self.role_map:
            return False
        
        try:
            if self.accessor.delete_role(rolename):
                del self.role_map[rolename]
                return True
            else:
                return False
        except Exception as e:
            raise AuthException(e)

    def grant_privilege_to_role(self, rolename, path, privilege_id):
        role = self.get_role(rolename)
        
        if role is None:
            raise AuthException(f"No such role {rolename}")
        
        try:
            if role.has_privilege(path, privilege_id):
                return False
            
            privileges_copy = set(role.get_privileges(path))
            role.add_privilege(path, privilege_id)
            
            self.accessor.save_role(role)
            return True
        except Exception as e:
            role.set_privileges(path, privileges_copy)
            raise AuthException(e)

    def revoke_privilege_from_role(self, rolename, path, privilege_id):
        role = self.get_role(rolename)
        
        if role is None:
            raise AuthException(f"No such role {rolename}")
        
        try:
            if not role.has_privilege(path, privilege_id):
                return False
            
            role.remove_privilege(path, privilege_id)
            
            self.accessor.save_role(role)
            return True
        except Exception as e:
            role.add_privilege(path, privilege_id)
            raise AuthException(e)

    def reset(self):
        self.accessor.reset()
        self.role_map.clear()

    def list_all_roles(self):
        rtlist = sorted(list(set(self.accessor.list_all_roles())))
        return rtlist

    def replace_all_roles(self, roles):
        try:
            self.reset()
            self.role_map.update(roles)
            
            for role in self.role_map.values():
                self.accessor.save_role(role)
        except Exception as e:
            raise AuthException(e)

class Role:
    pass
