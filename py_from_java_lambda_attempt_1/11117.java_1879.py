Here is the translation of the Java code into Python:

```Python
class NewProjectPanelManager:
    def __init__(self, tool):
        self.project_type_panel = ProjectTypePanel(self)
        self.select_project_panel = SelectProjectPanel(self)
        self.server_info_panel = ServerInfoPanel(self)
        self.project_manager = tool.get_project_manager()
        self.tool = tool

    def can_finish(self):
        if not self.project_type_panel.is_valid_information():
            return False
        if not self.project_type_panel.is_shared_project() and self.select_project_panel.is_valid_information():
            return True
        if self.repository_panel is None:
            return False
        if self.repository_panel.is_valid_information() and (self.project_access_panel is None or 
                self.project_access_panel.is_valid_information()) and self.select_project_panel.is_valid_information():
            return True
        return False

    def has_next_panel(self):
        if self.current_wizard_panel == self.select_project_panel:
            if self.select_project_panel.is_valid_information() and self.project_type_panel.is_valid_information() and not self.project_type_panel.is_shared_project():
                return False
        return self.current_wizard_panel != self.select_project_panel

    def has_previous_panel(self):
        return self.current_wizard_panel != self.project_type_panel

    def get_initial_panel(self):
        self.current_wizard_panel = self.project_type_panel
        return self.current_wizard_panel

    def get_next_panel(self):
        if self.current_wizard_panel is None:
            self.current_wizard_panel = self.project_type_panel
        elif self.current_wizard_panel == self.project_type_panel:
            if self.project_type_panel.is_shared_project():
                self.current_wizard_panel = self.server_info_panel
                self.server_info_panel.set_server_info(self.project_manager.get_most_recent_server_info())
            else:
                server = None
                server_info = None
                self.current_wizard_panel = self.select_project_panel
        elif self.current_wizard_panel == self.server_info_panel:
            if not is_server_info_valid(self.server_info_panel.get_server_name(), 
                                        self.server_info_panel.get_port_number()):
                return self.server_info_panel
            try:
                known_users = server.get_all_users()
                repository_names = server.get_repository_names()
                include_anonymous_access_control = server.anonymous_access_allowed()
                if self.repository_panel is None:
                    self.repository_panel = RepositoryPanel(self, 
                                                            self.server_info_panel.get_server_name(), 
                                                            repository_names, 
                                                            server.is_read_only())
                self.current_wizard_panel = self.repository_panel
            except RemoteException as e:
                status_message = "Error accessing remote server on " + self.server_info_panel.get_server_name()
        elif self.current_wizard_panel == self.repository_panel:
            if not self.repository_panel.create_repository():
                return self.repository_panel
            try:
                project_access_panel = ProjectAccessPanel(known_users, 
                                                            server.get_user(), 
                                                            new ArrayList<User>(), 
                                                            self.repository_panel.get_repository_name(), 
                                                            include_anonymous_access_control, 
                                                            False, tool)
            except IOException as e:
                msg.error(self, "Error creating project access panel")
        elif self.current_wizard_panel == self.project_access_panel:
            return self.select_project_panel
        else:
            if server is not None:
                try:
                    repository = server.create_repository(self.repository_panel.get_repository_name())
                    repository.set_user_list(project_access_panel.get_project_users(), 
                                            project_access_panel.allow_anonymous_access())
                except DuplicateNameException as e:
                    status_message = "Repository " + self.repository_panel.get_repository_name() + " exists"
                except UserAccessException as exc:
                    status_message = "Could not update the user list: " + exc.get_message()
            return None

    def finish(self):
        project_locator = self.select_project_panel.get_project_locator()
        if server is not None:
            try:
                repository = server.create_repository(self.repository_panel.get_repository_name())
                repository.set_user_list(project_access_panel.get_project_users(), 
                                        project_access_panel.allow_anonymous_access())
            except DuplicateNameException as e:
                status_message = "Repository " + self.repository_panel.get_repository_name() + " exists"
            except UserAccessException as exc:
                status_message = "Could not update the user list: " + exc.get_message()
        else:
            try:
                repository = server.create_repository(self.repository_panel.get_repository_name())
                repository.set_user_list(project_access_panel.get_project_users(), 
                                        project_access_panel.allow_anonymous_access())
            except DuplicateNameException as e:
                status_message = "Repository " + self.repository_panel.get_repository_name() + " exists"
            except UserAccessException as exc:
                status_message = "Could not update the user list: " + exc.get_message()
        Preferences.set_property(Preferences.LAST_NEW_PROJECT_DIRECTORY, 
                                 project_locator.get_location())
        Preferences.store()

    def cancel(self):
        self.current_wizard_panel = None
        self.repository_panel = None
        if repository is not None:
            try:
                repository.disconnect()
            except RemoteException as e:
                status_message = "Error disconnecting from the repository"

    def initialize(self):
        self.current_wizard_panel = None
        self.select_project_panel.initialize()
        self.server_info_panel.initialize()

    def get_panel_size(self):
        return get_my_panel_size()

    def set_wizard_manager(self, wizard_manager):
        self.wizard_manager = wizard_manager

    def get_wizard_manager(self):
        return self.wizard_manager

    def get_new_project_location(self):
        return new_project_locator

    def get_project_repository(self):
        return repository

    def is_shared_project(self):
        return project_type_panel.is_shared_project()

def is_server_info_valid(server_name, port_number):
    if server is not None and server_info is not None and server_info.get_server_name().equals(server_name) and 
       server_info.get_port_number() == port_number and server.is_connected():
        return True
    repository_panel = None

    try:
        server = project_manager.get_repository_server_adapter(server_name, port_number, True)
        if server.is_connected():
            server_info = project_manager.get_most_recent_server_info()
            return True
    except RemoteException as e:
        status_message = "Could not connect to server " + server_name + ", port " + str(port_number)

def get_my_panel_size():
    panel1 = ProjectAccessPanel(["nobody"], "user", new ArrayList<User>(), "MyRepository", True, False)
    panel2 = RepositoryPanel(self, "ServerOne", ["MyRepository", "NewStuff", "Repository_A", "Repository_B"], False)
    d1 = panel1.get_preferred_size()
    d2 = panel2.get_preferred_size()
    return new Dimension(max(d1.width, d2.width), max(d1.height, d2.height))
```

Note: This translation is not a direct copy-paste from Java to Python. It's an interpretation of the code in terms of Python syntax and semantics.