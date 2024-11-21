import os
from datetime import timedelta

class RepositoryManager:
    def __init__(self, root_dir_file, enable_local_passwords=False, default_password_expiration_days=0, anonymous_access_allowed=True):
        self.root_dir_file = root_dir_file
        if not os.path.exists(self.root_dir_file) or not os.path.isdir(self.root_dir_file):
            raise Exception(f"{root_dir_file} is not a directory")
        if not os.access(self.root_dir_file, os.W_OK):
            raise Exception(f"Failed to make directory for {self.root_dir_file}")
        self.anonymous_access_allowed = anonymous_access_allowed
        self.user_mgr = UserManager(enable_local_passwords, default_password_expiration_days)

    def get_root_dir(self):
        return self.root_dir_file

    def create_repository(self, current_user, name):
        if not self.is_anonymous_user(current_user):
            self.validate_user(current_user)
        if not NamingUtilities.is_valid_project_name(name):
            raise Exception(f"Invalid repository name: {name}")
        if self.repository_map.get(name) is not None:
            raise DuplicateFileException("Repository named {} already exists".format(name))
        repo_dir = os.path.join(self.root_dir_file, NamingUtilities.mangle(name))
        try:
            os.mkdir(repo_dir)
        except Exception as e:
            raise IOException(f"Failed to make directory for {repo_dir}")
        repository = Repository(self, current_user, repo_dir, name)
        self.log(name, None, "repository created", current_user)
        self.repository_map[name] = repository
        return repository

    def get_repository_names(self):
        names = []
        for path in os.listdir(self.root_dir_file):
            if not os.path.isdir(os.path.join(self.root_dir_file, path)):
                continue
            if not NamingUtilities.is_valid_mangled_name(path):
                self.log(None, None, "Ignoring repository directory with bad name: {}".format(path), None)
                continue
            names.append(NamingUtilities.demangle(path))
        return sorted(names)

    def get_repository(self, current_user, name):
        if not self.is_anonymous_user(current_user):
            self.validate_user(current_user)
        repo = self.repository_map.get(name)
        if repo is not None:
            repo.validate_read_privilege(current_user)
        return repo

    def delete_repository(self, current_user, name):
        if not self.is_anonymous_user(current_user):
            self.validate_user(current_user)
        repository = self.repository_map.get(name)
        if repository is None:
            return
        try:
            os.rmdir(os.path.join(self.root_dir_file, NamingUtilities.mangle(name)))
        except Exception as e:
            raise IOException(f"Failed to remove directory for {name}")
        del self.repository_map[name]

    def get_all_users(self):
        if not self.is_anonymous_user():
            return []
        try:
            users = self.user_mgr.get_users()
            return users
        except Exception as e:
            log.error("Error while accessing user list: {}".format(e))
            raise IOException("Failed to read user list")

    def validate_user(self, current_user):
        if not self.user_mgr.is_valid_user(current_user):
            raise UserAccessException("{} is unknown to this repository manager".format(current_user))

    @staticmethod
    def get_elapsed_time_since(t):
        elapsed = int((datetime.datetime.now().timestamp() - t) / 1000)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02}:{minutes:02}:{seconds:02}"

    def add_handle(self):
        pass

    def drop_handle(self):
        pass

    @staticmethod
    def log(repository_name, path, msg, user):
        if repository_name is not None:
            print(f"[{repository_name}]")
        host = get_rmi_client()
        if user is not None and host is not None:
            print(f"{user}@{host}")
        elif user is None and host is not None:
            print(host)
        else:
            print(msg)

    @staticmethod
    def list_repositories(root_dir_file, include_user_access_details):
        names = RepositoryManager.get_repository_names(root_dir_file)
        if len(names) == 0:
            print("    <No repositories have been created>")
        for name in names:
            repo_dir = os.path.join(root_dir_file, NamingUtilities.mangle(name))
            root_path = repo_dir
            is_indexed = IndexedLocalFileSystem.is_indexed(root_path)
            type = "Indexed Filesystem"
            if not is_indexed and IndexedLocalFileSystem.has_indexed_structure(root_path):
                type += f" (V{IndexedLocalFileSystem.read_index_version(root_path)})"
            else:
                type = "Mangled Filesystem"

            print(f"{name} - uses {type}")

            if include_user_access_details:
                Repository.list_user_permissions(repo_dir, "")

    @staticmethod
    def mark_all_repositories_for_index_migration(server_dir):
        names = RepositoryManager.get_repository_names(server_dir)
        count = 0
        for name in names:
            if Repository.mark_repository_for_index_migration(server_dir, name, True):
                count += 1

        if count == 0:
            print("All repositories are already indexed")

    def __init__(self): pass


class UserManager:

    def get_users(self):
        return []

    def is_valid_user(self, user):
        return False
