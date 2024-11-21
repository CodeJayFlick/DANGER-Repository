Here is the translation of the Java code into Python:

```Python
class DefaultProjectManager:
    def __init__(self):
        self.recently_opened_projects = []
        self.recently_viewed_projects = []
        self.user_tool_chest = None
        self.server_info = None
        self.last_opened_project = None
        self.current_project = None

    def get_active_project(self) -> 'Project':
        return self.current_project

    def create_project(self, project_locator: ProjectLocator, repository_adapter: RepositoryAdapter,
                       remember: bool) -> 'Project':
        if self.current_project is not None:
            raise Exception("Current project must be closed before establishing a new active project")

        try:
            current_project = DefaultProject(self, project_locator, repository_adapter)
        except LockException as e:
            raise IOException(str(e))

        if remember:
            self.add_project_to_list(self.recently_opened_projects, project_locator)
            self.last_opened_project = project_locator
            Preferences.store()

        return current_project

    def open_project(self, project_locator: ProjectLocator, do_restore: bool,
                     reset_owner: bool) -> 'Project':
        if self.current_project is not None:
            raise Exception("Current project must be closed before establishing a new active project")

        try:
            current_project = DefaultProject(self, project_locator, reset_owner)
            if do_restore:
                current_project.restore()
            return current_project
        except LockException as e:
            return None
        except ReadOnlyException as e:
            print(f"Read-only Project! {str(e)}")
        finally:
            if self.current_project is None:
                File(dir_file).delete()

    def get_recent_projects(self) -> list[ProjectLocator]:
        return [project_locator for project_locator in self.recently_opened_projects]

    def get_recent_viewed_projects(self) -> list[URL]:
        return [url for url in self.recently_viewed_projects]

    def get_last_opened_project(self) -> ProjectLocator:
        if Preferences.get(LAST_OPENED_PROJECT, None):
            project_path = Preferences.get(LAST_OPENED_PROJECT)
            return get_locator_from_project_path(project_path)

    def set_last_opened_project(self, project_locator: ProjectLocator):
        Preferences.set(LAST_OPENED_PROJECT, str(project_locator))

    def delete_project(self, project_locator: ProjectLocator) -> bool:
        if not project_locator.get_project_dir().exists():
            raise Exception(f"Directory {project_locator.get_project_dir()} does not exist")

        did_delete = (FileUtilities.delete_dir(project_locator.get_project_dir()) and
                      (!file.exists() or file.delete()))
        self.forget_project(project_locator)
        return did_delete

    def forget_project(self, project_locator: ProjectLocator):
        if project_locator == self.last_opened_project:
            self.last_opened_project = None
        self.recently_opened_projects.remove(project_locator)

    def remember_project(self, project_locator: ProjectLocator):
        if not self.recently_opened_projects.contains(project_locator):
            self.add_project_to_list(self.recently_opened_projects, project_locator)
            Preferences.store()

    def forget_viewed_project(self, url: URL):
        self.recently_viewed_projects.remove(url)

    def remember_viewed_project(self, url: URL):
        if not self.recently_viewed_projects.contains(url):
            self.recently_viewed_projects.add(0, url)
            if len(self.recently_viewed_projects) > RECENT_PROJECTS_LIMIT:
                self.recently_viewed_projects.remove(len(self.recently_viewed_projects) - 1)

    def project_exists(self, project_locator: ProjectLocator) -> bool:
        return project_locator.get_project_dir().exists()

    def get_repository_server_adapter(self, host: str, port_number: int,
                                       force_connect: bool) -> RepositoryServerAdapter:
        repository_server_adapter = ClientUtil.get_repository_server(host, port_number, force_connect)
        self.server_info = repository_server_adapter.get_server_info()
        Preferences.store()
        return repository_server_adapter

    def get_most_recent_server_info(self) -> ServerInfo:
        return self.server_info

    def add_default_tools(self, tool_chest: ToolChest):
        set_of_tool_templates = ToolUtils.get_default_application_tools()

        if not set_of_tool_templates.is_empty():
            for template in set_of_tool_templates:
                tool_chest.replace_tool_template(template)

    def install_tools(self, tool_chest: ToolChest) -> None:
        LOG.debug("No tools found; Installing default tools")

        recovery_directory = self.get_most_recent_valid_project_directory()
        if recovery_directory is not None:
            LOG.debug("\tno recent project directories found")
            self.add_default_tools(tool_chest)
        else:
            LOG.debug("Found the following default tools:")
            for tool in set_of_tool_templates:
                LOG.debug("-" + str(tool))
            LOG.debug("Found existing tools; merging existing tools:")

    def get_most_recent_valid_project_directory(self) -> File:
        list_files = GenericRunInfo.get_previous_application_settings_dirs_by_time()
        if not list_files.is_empty():
            for file in list_files:
                if file.getName().equals(APPLICATION_TOOLS_DIR_NAME):
                    return file
        return None

    def merge_default_tools_into_existing(self, default_tools: Set[ToolTemplate],
                                            user_tools: Set[ToolTemplate]) -> set[ToolTemplate]:
        all_tools = {}
        for tool in default_tools:
            all_tools.update({tool.getName(): tool})
        for tool in user_tools:
            if not all_tools.get(tool.getName()):
                all_tools.update({tool.getName(): tool})

    def save_tool(self, template: ToolTemplate) -> URL:
        try:
            return ToolUtils.write_tool_template(template)
        except Exception as e:
            LOG.error(f"Unable to save user tool '{template.getName()}': {str(e)}")

    def get_locator_from_project_path(self, path: str) -> ProjectLocator:
        if not GhidraURL.is_local_project_url(path):
            return None
        try:
            url = GhidraURL.to_URL(path)
            if GhidraURL.local_project_exists(url):
                return GhidraURL.get_project_storage_locator(url)
        except Exception as e:
            LOG.error(f"Invalid project path: {path}")

    def populate_project_locator_list(self, list: List[ProjectLocator], property_name: str) -> None:
        preferences = Preferences.get(property_name)

        if not preferences.is_empty():
            for token in preferences.split(PROJECT_PATH_SEPARATOR):
                try:
                    url = GhidraURL.to_URL(token)
                    if GhidraURL.local_project_exists(url):
                        list.add(ProjectLocator.from_string(str(url)))
                except Exception as e:
                    LOG.error(f"Invalid project path/URL: {token}")

    def update_preferences(self) -> None:
        self.set_project_locator_property(self.recently_opened_projects, RECENT_PROJECTS)
        if self.server_info is not None:
            Preferences.set(SERVER_INFO, str(self.server_info))
        Preferences.store()

    def set_project_locator_property(self, list: List[ProjectLocator], property_name: str) -> None:
        buffer = StringBuffer()
        for i in range(len(list)):
            project_locator = list[i]
            if i < len(list) - 1:
                buffer.append(str(project_locator))
                buffer.append(PROJECT_PATH_SEPARATOR)
            else:
                buffer.append(str(project_locator))

    def set_project_url_property(self, list: List[URL], property_name: str) -> None:
        buffer = StringBuffer()
        for url in list:
            if not GhidraURL.is_local_project_url(url):
                continue
            try:
                buffer.append(str(url))
                if i < len(list) - 1:
                    buffer.append(PROJECT_PATH_SEPARATOR)
            except Exception as e:
                LOG.error(f"Invalid project path/URL: {str(e)}")

    def get_server_info(self, str: str) -> ServerInfo:
        host = None
        port_str = None

        if not st.hasMoreTokens():
            return None

        while st.hasMoreTokens():
            token = st.nextToken()
            if host is None:
                host = token
            else:
                port_str = token

    def project_closed(self, project: DefaultProject) -> None:
        if project == self.current_project:
            self.current_project = None
        TransientDataManager.clear_all()

def main():
    manager = DefaultProjectManager()
    # your code here...

if __name__ == "__main__":
    main()
```

Please note that this is a direct translation of the Java code into Python, and it may not be perfect.