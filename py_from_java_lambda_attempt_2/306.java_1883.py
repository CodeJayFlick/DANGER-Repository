Here is the equivalent Python code:

```Python
class ProgramURLUtils:
    @staticmethod
    def get_url_from_program(program):
        file = program.domain_file()
        project_locator = file.project_locator()
        if not project_locator:
            return None
        
        repository = file.parent().project_data().repository()
        if repository:
            server_info = repository.server_info()
            if file.is_versioned():
                return GhidraURL.make_url(server_info.server_name, server_info.port_number,
                                          repository.name, file.pathname())
        
        return ProgramURLUtils.hack_add_local_domain_file_path(project_locator.url(), file.pathname())

    @staticmethod
    def hack_add_local_domain_file_path(local_project_url, pathname):
        try:
            return URL(f"{local_project_url}!{pathname}")
        except ValueError as e:
            raise AssertionError(e)

    @staticmethod
    def get_file_for_hacked_up_ghidra_url(project, ghidra_url):
        try:
            url_string = str(ghidra_url)
            bang_loc = url_string.find('!')
            if bang_loc == -1:
                project_data = project.project_data(ghidra_url)
                return None if not project_data else project_data.get_file(url_string.path)

            local_proj_url = URL(f"{url_string[:bang_loc]}")
            project_data = project.project_data(local_proj_url)
            return project_data.get_file(url_string[bang_loc + 1:])
        except ValueError as e:
            raise AssertionError(e)

    @staticmethod
    def open_hacked_up_ghidra_url(program_manager, project, ghidra_url, state):
        file = ProgramURLUtils.get_file_for_hacked_up_ghidra_url(project, ghidra_url)
        return program_manager.open_program(file, DomainFile.DEFAULT_VERSION, state)

class GhidraURL:
    @staticmethod
    def make_url(server_name, port_number, repository_name, pathname):
        # implement this method as per your requirements

class URL:
    def __init__(self, url_string):
        self._url_string = url_string
    
    def to_external_form(self):
        return self._url_string
    
    @staticmethod
    def find(substring):
        try:
            return self._url_string.find(substring)
        except ValueError as e:
            raise AssertionError(e)

    def path(self):
        # implement this method as per your requirements

class DomainFile:
    DEFAULT_VERSION = 0
    
    def __init__(self, project_locator=None):
        self.project_locator = project_locator
        self.parent()  # assume this is a setter or getter for parent attribute

    @property
    def pathname(self):
        return 'path'

    @property
    def domain_file(self):
        return self

class ProgramManager:
    def __init__(self, program=None):
        self.program = program
    
    def open_program(self, file, version, state):
        # implement this method as per your requirements

class ProjectData:
    def __init__(self, repository=None):
        self.repository = repository
        self.project_data()  # assume this is a setter or getter for project data attribute

    @property
    def get_file(self, pathname):
        return DomainFile()
```

Please note that the above Python code does not include all the classes and methods as they are quite complex. It only includes those which were necessary to translate the given Java code into equivalent Python code.