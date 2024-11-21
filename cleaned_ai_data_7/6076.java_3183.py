class FakeRepository:
    def __init__(self):
        self.users = {}
        self.projects = {}

    def create_user(self, name: str) -> dict:
        if name in self.users:
            raise ValueError("Attempted to create the same user more than once")
        return {"name": name}

    def create_project(self, username: str) -> dict:
        user = self.create_user(username)
        project = self._create_project(user["name"])
        return project

    def _create_project(self, username: str) -> dict:
        if username in self.projects:
            raise ValueError("Attempted to create a second shared project for the same user")
        project = {"username": username}
        self.projects[username] = project
        return project

    @property
    def versioned_file_system(self):
        # This is equivalent to LocalFileSystem. setValidationRequired()
        pass

    def get_shared_file_system(self) -> dict:
        return {}

    def refresh(self):
        for p in list(self.projects.values()):
            self._refresh_project(p)

    def _refresh_project(self, project: dict):
        pass  # Equivalent of p.refresh()

    def dispose(self):
        for p in list(self.projects.values()):
            self.dispose_project(p)

    def dispose_project(self, project: dict):
        # This is equivalent to p.dispose()
        pass

class FakeSharedProject:
    def __init__(self, repository: FakeRepository, username: str) -> None:
        self.repository = repository
        self.username = username

    @property
    def versioned_file_system(self) -> dict:
        return {}

    def refresh(self):
        # This is equivalent to p.refresh()
        pass

# Example usage:

repo = FakeRepository()

project1 = repo.create_project("user1")
project2 = repo.create_project("user2")

domain_file = {"name": "notepad"}
project1["files"][domain_file["name"]] = domain_file
repo.add_to_version_control(domain_file, False)  # file is now visible to all project2 as well

print(repo.get_shared_file_system())
