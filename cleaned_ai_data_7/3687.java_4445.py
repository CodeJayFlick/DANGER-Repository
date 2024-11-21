class RecentlyOpenedArchiveAction:
    def __init__(self, plugin: 'DataTypeManagerPlugin', archive_path: str, displayed_path: str = None, menu_group: str = None):
        self.plugin = plugin
        self.archive_path = archive_path
        if displayed_path is not None and menu_group is not None:
            super().__init__(f"{menu_group}: {archive_path}", f"Opens the indicated archive in the data type manager.", False)
        else:
            super().__init__("Open Archive", "Opens the indicated archive in the data type manager.", False)

    def set_menu_bar_data(self, menu_data: 'MenuData'):
        self.menu_bar_data = menu_data

    @property
    def description(self) -> str:
        return "Opens the indicated archive in the data type manager."

    @property
    def enabled(self) -> bool:
        return True

    def get_display_path(self, filepath: str):
        if project_pathname := DataTypeManagerHandler.parse_project_pathname(filepath):
            return f"{project_pathname[0]}:{project_pathname[1]}"
        else:
            return filepath

    @property
    def menu_bar_data(self) -> 'MenuData':
        return self._menu_bar_data

    def action_performed(self, context: 'ActionContext'):
        if project_name is None:
            archive_manager = self.plugin.get_datatype_manager_handler()
            path = Path(archive_path)
            task = OpenArchiveTask(archive_manager, path)
            TaskLauncher(task).start(plugin.get_provider().get_component())
        else:
            df = plugin.get_project_archive_file(project_name, archive_path)
            if df is not None:
                self.plugin.open_archive(df)
            else:
                Msg.show_error(self, "Project Archive Open Error", f"Project data type archive not found: {self.menu_bar_data.get_menu_item_name()}")

class OpenArchiveTask(Task):
    def __init__(self, archive_manager: 'DataTypeManagerHandler', path: Path):
        super().__init__("Opening Archive " + path.path.name, False, False, True)
        self.archive_manager = archive_manager
        self.archive_path = path

    @property
    def description(self) -> str:
        return f"Opening Archive {self.archive_path.path.name}"

    def run(self, monitor: 'TaskMonitor'):
        try:
            self.archive_manager.open_archive(self.archive_path.path, False, True)
        except Exception as e:
            DataTypeManagerHandler.handle_archive_file_exception(plugin, self.archive_path.path, e)

class MenuData:
    pass

class Path:
    @property
    def path(self) -> str:
        return self._path

    def __init__(self, path: str):
        self._path = path

class TaskMonitor:
    pass
