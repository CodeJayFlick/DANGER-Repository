class SetupProjectPanelManager:
    def __init__(self, tool, server_info):
        self.server_panel = ServerInfoPanel(self)
        self.project_mgr = tool.get_project_manager()
        self.current_server_info = server_info
        self.tool = tool

    def can_finish(self):
        if not hasattr(self, 'repository_panel'):
            return False
        if self.repository_panel.is_valid_information():
            if self.repository_panel.create_repository():
                if not hasattr(self, 'project_access_panel') or self.project_access_panel.is_valid_information():
                    return True
                else:
                    return False
            else:
                return True
        else:
            return False

    def has_next_panel(self):
        if getattr(self, 'current_wizard_panel', None) == self.server_panel:
            return True
        elif (getattr(self, 'current_wizard_panel', None) == self.repository_panel and 
              self.repository_panel.create_repository()):
            return True
        else:
            return False

    def has_previous_panel(self):
        return getattr(self, 'current_wizard_panel', None) != self.server_panel

    def get_initial_panel(self):
        if not hasattr(self, 'current_wizard_panel'):
            self.current_wizard_panel = self.server_panel
        return self.current_wizard_panel

    def get_next_panel(self):
        if not hasattr(self, 'current_wizard_panel') or getattr(self, 'current_wizard_panel', None) == self.server_panel:
            server_name = self.server_panel.get_server_name()
            port_number = self.server_panel.get_port_number()
            if not is_server_info_valid(server_name, port_number):
                return self.server_panel
        elif getattr(self, 'current_wizard_panel', None) == self.repository_panel:
            repository_name = self.repository_panel.get_repository_name()
            if not self.repository_panel.create_repository():
                try:
                    access_list = []
                    allow_anonymous_access = False
                    if hasattr(self, 'project_access_panel') and \
                       self.project_access_panel.get_project_users() is not None:
                        access_list = self.project_access_panel.get_project_users()
                        allow_anonymous_access = self.project_access_panel.allow_anonymous_access()
                    else:
                        user = User(server_info.getUser(), User.ADMIN)
                        access_list.append(user)
                        allow_anonymous_access = False
                    repository = server.create_repository(repository_name, access_list, allow_anonymous_access)
                except (DuplicateNameException, UserAccessException) as e:
                    self.status_message = str(e)
                except NotConnectedException as e:
                    if not hasattr(self, 'status_message'):
                        self.status_message = "Not connected to server " + server_info.getServerName() + ": " + str(e)
            else:
                check_new_repository_access_panel()
        elif getattr(self, 'current_wizard_panel', None) == self.project_access_panel:
            return None
        return self.current_wizard_panel

    def get_previous_panel(self):
        if hasattr(self, 'project_access_panel'):
            self.current_wizard_panel = self.repository_panel
        else:
            self.current_wizard_panel = self.server_panel
        return self.current_wizard_panel

    def finish(self):
        try:
            create_new_repository = self.repository_panel.create_repository()
            if not create_new_repository:
                repository_name = self.repository_panel.get_repository_name()
                if hasattr(self, 'repository'):
                    self.repository.disconnect()
                else:
                    user_list = [User(server_info.getUser(), User.ADMIN)]
                    allow_anonymous_access = False
                    if hasattr(self, 'project_access_panel') and \
                       self.project_access_panel.get_project_users() is not None:
                        access_list = self.project_access_panel.get_project_users()
                        allow_anonymous_access = self.project_access_panel.allow_anonymous_access()
                    else:
                        user = User(server_info.getUser(), User.ADMIN)
                        access_list.append(user)
                        allow_anonymous_access = False
                    repository = server.create_repository(repository_name, access_list, allow_anonymous_access)
        except (DuplicateNameException, UserAccessException) as e:
            self.status_message = str(e)
        except NotConnectedException as e:
            if not hasattr(self, 'status_message'):
                self.status_message = "Not connected to server " + server_info.getServerName() + ": " + str(e)
        except IOException as exc:
            msg = str(exc)
            if msg is None:
                msg = str(exc)
            self.status_message = "Error occurred while updating the user list: " + msg
        finally:
            wizard_mgr.close()

    def cancel(self):
        self.current_wizard_panel = None
        if hasattr(self, 'repository'):
            self.repository.disconnect()
        else:
            server = None

    def initialize(self):
        self.current_wizard_panel = None
        if hasattr(self, 'repository_panel'):
            self.repository_panel.initialize()
        if hasattr(self, 'project_access_panel'):
            self.project_access_panel.initialize()

    def get_panel_size(self):
        return get_my_panel_size()

    def set_wizard_manager(self, wizard_mgr):
        self.wizard_mgr = wizard_mgr

    def get_wizard_manager(self):
        return self.wizard_mgr

    def get_project_repository(self):
        if hasattr(self, 'repository'):
            return self.repository
        else:
            return None

    def get_project_repository_name(self):
        if hasattr(self, 'repository_panel'):
            return self.repository_panel.get_repository_name()
        else:
            return None


def is_server_info_valid(server_name, port_number):
    if server and current_server_info and server_info.getServerName() == server_name and \
       server_info.getPortNumber() == port_number and server.isConnected():
        return True
    server = None
    server_info = None
    repository_panel = None

    try:
        server = project_mgr.get_repository_server_adapter(server_name, port_number, True)
        if server.isConnected():
            server_info = project_mgr.get_most_recent_server_info()
            return True
    except NotConnectedException as e:
        self.status_message = "Could not connect to server " + server_name + ", port " + str(port_number)

    return False


def get_my_panel_size():
    panel1 = ProjectAccessPanel(["nobody"], "user", [], "MyRepository", True, False)
    panel2 = RepositoryPanel(self, "ServerOne",
                              ["MyRepository", "NewStuff", "Repository_A", "Repository_B"],
                              False)

    d1 = panel1.get_preferred_size()
    d2 = panel2.get_preferred_size()

    return Dimension(max(d1.width, d2.width), max(d1.height, d2.height))
