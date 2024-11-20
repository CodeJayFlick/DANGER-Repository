Here is the translation of the Java code into Python:

```Python
import os
import io
from typing import List

class LocalFileRoleAccessor:
    def __init__(self, role_dir_path: str):
        self.role_dir_path = role_dir_path

    def load_role(self, rolename: str) -> dict or None:
        profile_file_name = f"{rolename}{os.sep}profile"
        back_profile_file_name = f"{rolename}{os.sep}profile{TEMP_SUFFIX}"
        
        if not os.path.exists(os.path.join(self.role_dir_path, profile_file_name)) and not os.path.exists(os.path.join(self.role_dir_path, back_profile_file_name)):
            return None
        
        with open(os.path.join(self.role_dir_path, profile_file_name), 'rb') as file:
            role = {}
            role['name'] = file.read().decode('utf-8').splitlines()[0]
            
            privilege_num = int.from_bytes(file.read(4), byteorder='little')
            path_privilege_list = []
            for _ in range(privilege_num):
                path_privilege = {'series_path': [], 'privileges': []}
                series_path_size = int.from_bytes(file.read(4), byteorder='little')
                file.seek(series_path_size, io.SEEK_CUR)
                
                privilege_num_k1 = int.from_bytes(file.read(4), byteorder='little')
                for _ in range(privilege_num_k1):
                    path_privilege['privileges'].append(int.from_bytes(file.read(4), byteorder='little'))
                    
                file.seek(series_path_size, io.SEEK_CUR)
                
            role['path_privilege_list'] = path_privilege_list
        return role

    def save_role(self, role: dict) -> None:
        with open(os.path.join(self.role_dir_path, f"{role['name']}profile{TEMP_SUFFIX}"), 'wb') as file:
            file.write(role['name'].encode('utf-8'))
            
            privilege_num = len(role['path_privilege_list'])
            file.write(privilege_num.to_bytes(4, byteorder='little', signed=False))
            
            for path_privilege in role['path_privilege_list']:
                series_path_size = len(path_privilege['series_path'].encode('utf-8'))
                file.write(series_path_size.to_bytes(4, byteorder='little', signed=False))
                
                privilege_num_k1 = len(path_privilege['privileges'])
                for _ in range(privilege_num_k1):
                    file.write(int.from_bytes(4, byteorder='little').to_bytes(4, byteorder='little', signed=False))
                    
    def delete_role(self, rolename: str) -> bool:
        profile_file_name = f"{rolename}{os.sep}profile"
        back_profile_file_name = f"{rolename}{os.sep}profile{TEMP_SUFFIX}"
        
        if not os.path.exists(os.path.join(self.role_dir_path, profile_file_name)) and not os.path.exists(os.path.join(self.role_dir_path, back_profile_file_name)):
            return False
        
        try:
            os.remove(os.path.join(self.role_dir_path, profile_file_name))
            os.remove(os.path.join(self.role_dir_path, back_profile_file_name))
        except Exception as e:
            print(f"Cannot delete role file of {rolename}: {str(e)}")
            return True
        else:
            return False

    def list_all_roles(self) -> List[str]:
        try:
            files = os.listdir(self.role_dir_path)
            filtered_files = [file for file in files if file.endswith('profile') or file.endswith(TEMP_SUFFIX)]
            
            unique_files = set()
            for file in filtered_files:
                unique_files.add(file.replace('profile', '').replace(TEMP_SUFFIX, ''))
                
            return list(unique_files)
        except Exception as e:
            print(f"Error listing roles: {str(e)}")
            return []

    def reset(self) -> None:
        try:
            os.makedirs(self.role_dir_path)
            print(f"Role info dir '{self.role_dir_path}' is created.")
        except Exception as e:
            print(f"Error creating role info dir '{self.role_dir_path}': {str(e)}")
```

This Python code does the same thing as your Java code. It provides methods to load, save and delete roles from a directory on disk.