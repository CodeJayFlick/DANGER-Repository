Here is the translation of the Java code into Python:

```Python
class GhidraURLConnection:
    GHIDRA_OK = 200
    GHIDRA_UNAUTHORIZED = 401
    GHIDRA_NOT_FOUND = 404
    GHIDRA_WRAPPED_CONTENT = "GhidraWrappedContent"
    REPOSITORY_SERVER_CONTENT = "RepositoryServer"

    def __init__(self, ghidra_url):
        self.response_code = -1
        self.protocol_connector = None
        self.project_data = None
        self.ref_object = None
        self.read_only = True

        try:
            super().__init__(ghidra_url)
        except MalformedURLException as e:
            raise Exception("Invalid URL") from e

    def is_readonly(self):
        if not hasattr(self, 'connected'):
            return self.read_only  # connect intention
        try:
            return self.protocol_connector.is_readonly()
        except NotConnectedException as e:
            raise AssertException(e)  # unexpected

    def set_readonly(self, state):
        if hasattr(self, 'connected'):
            raise Exception("Already connected")
        self.read_only = state

    @property
    def repository_name(self):
        return self.protocol_connector.repository_name()

    @property
    def folder_path(self):
        return self.protocol_connector.folder_path()

    @property
    def folder_item_name(self):
        return self.protocol_connector.folder_item_name()

    def get_response_code(self) -> int:
        if hasattr(self, 'response_code') and self.response_code != -1:
            return self.response_code

        try:
            content = self.get_content()
            return 200
        except IOException as e:
            raise Exception("Error connecting to server") from e

    def get_content_type(self) -> str:
        if not hasattr(self, 'connected') or self.ref_object is None:
            return "Unknown"
        if isinstance(self.ref_object, RepositoryServerAdapter):
            return REPOSITORY_SERVER_CONTENT
        elif isinstance(self.ref_object, GhidraURLWrappedContent):
            return GHIDRA_WRAPPED_CONTENT
        else:
            return "Unknown"

    def get_content(self) -> object:
        if not hasattr(self, 'connected'):
            self.connect()

        return self.ref_object

    @property
    def project_data(self) -> ProjectData:
        if not hasattr(self, 'project_data') or isinstance(self.project_data, TransientProjectData):
            try:
                content = self.get_content()
                # todo: implement logic to get transient project data
            except IOException as e:
                raise Exception("Error connecting to server") from e

    def connect(self) -> None:
        if hasattr(self, 'connected'):
            return  # already connected

        protocol_handler = self.protocol_connector
        response_code = -1

        try:
            local_project_locator = protocol_handler.local_project_locator()
            response_code = protocol_handler.connect(local_project_locator)
            if response_code != GHIDRA_OK:
                return

            project_data = ProjectFileManager(project_locator=local_project_locator, read_only=self.read_only, transient=False)

            self.ref_object = GhidraURLWrappedContent(self)
        except NotOwnerException as e:
            raise Exception("Unauthorized") from e
```

Note that Python does not have direct equivalent of Java's `package` declaration. Also, the code assumes that certain classes and methods are defined elsewhere in your project (e.g., `ProjectFileManager`, `TransientProjectManager`, etc.).