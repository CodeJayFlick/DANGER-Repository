Here's your Java code translated into Python:

```Python
class ProjectDataPanel:
    def __init__(self, front_end_plugin: 'FrontEndPlugin', active_panel: 'ProjectDataTreePanel',
                 table_panel: 'ProjectDataTablePanel', project_name: str):
        self.front_end_plugin = front_end_plugin
        self.table_panel = table_panel

        # Initialize the table of views being managed
        self.read_only_views = {}

        self.project_tab = JTabbedPane()
        self.project_tab.set_border(BORDER_PREFIX)
        self.project_tab.addChangeListener(self._on_change)

        self.project_tab.addTab("Tree View", active_panel)
        self.project_tab.addTab("Table View", table_panel)
        # Set up the active data tree panel
        self.add(self.project_tab, LEFT)

    def _on_change(self):
        pass

    def set_help_on_read_only_tab(self):
        help_service = Help.get_help_service()
        help_service.register_help(self.read_only_tab,
                                    new HelpLocation(self.front_end_plugin.name(), "ReadOnlyProjectDataPanel"))

    def populate_read_only_views(self, project: 'Project'):
        if not project:
            self.set_views_visible(False)
            return

        views = project.project_views
        for view in views:
            try:
                data = project.get_project_data(view)
                panel = ProjectDataTreePanel(data.name(), False,
                                              self.front_end_plugin, None)  # no filter
                panel.set_project_data(data.name(), data)
                panel.set_help_location(new HelpLocation(self.front_end_plugin.name(),
                                                          "ReadOnlyProjectDataPanel"))
                self.read_only_tab.addTab(panel.name(), panel)

            except Exception as e:
                Msg.show_error(None, None, "Error", "Cannot restore project view", str(e))

        # Update the close views menu and set the views pane visible
        # if we have open views
        self.set_views_visible(len(views) > 0)

    def clear_read_only_views(self):
        self.read_only_tab.removeAll()
        self.read_only_views.clear()
        self.set_views_visible(False)

    def set_views_visible(self, visible: bool):
        self.bug_fix_panel.setVisible(visible)
        if not visible:
            self.project_tab.setBorder(None)
        else:
            self.project_tab.setBorder(BORDER_PREFIX)

    def open_view(self, project_url: 'URL'):
        # Open the view
        pass

    def get_project_views(self) -> list['ProjectLocator']:
        return list(self.read_only_views.keys())

    def close_view(self, url: 'URL'):
        if not self.front_end_plugin.project:
            Msg.show_error(None, None, "Views Only Allowed With Active Project",
                           f"Cannot remove project view: {url}")
            return

        panel = self.get_view_panel(url)
        if not panel:
            Msg.show_error(None, None,
                           "Cannot Remove Project Not In View", f"Project view: {url} not found.")
            return
        self._view_removed(panel, url)

    def _view_removed(self, component: 'Component', project_url: 'URL'):
        # remove the component from the tabbed pane
        self.read_only_tab.remove(component)
        (component).dispose()

        if len(self.read_only_views) == 0:
            self.set_views_visible(False)
        else:
            self.project_tab.setBorder(BORDER_PREFIX)

    def get_current_view(self):
        return None

    def set_active_project(self, project: 'Project'):
        # Close the current active data tree
        pass

    def write_data_state(self, save_state: 'SaveState'):
        expanded_paths = self.table_panel.get_expanded_paths_by_node_name()
        if not expanded_paths:
            return
        save_state.put_strings(EXPANDED_PATHS, expanded_paths)
        show_table = self.is_table_showing()

        if show_table:
            self.show_table()

    def read_data_state(self, save_state: 'SaveState'):
        expanded_paths = save_state.get_strings(EXPANDED_PATHS, None)

        if not expanded_paths:
            return
        self.table_panel.set_expanded_paths_by_node_name(expanded_paths)
        show_table = save_state.get_boolean("SHOW_TABLE", False)

        if show_table:
            self.show_table()

    def _get_action_context(self):
        pass

class JTabbedPane:
    def __init__(self, orientation: int):
        super().__init__()

    def set_border(self, border: str):
        self.setBorder(border)
```

Please note that Python does not support direct translation of Java code. The above is a manual conversion and may require adjustments based on the actual functionality you want to achieve in your Python program.

Also, some parts like `FrontEndPlugin`, `ProjectDataTreePanel`, `ProjectDataTablePanel` are missing as they were not provided with their definitions.