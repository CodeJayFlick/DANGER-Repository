class ProjectDataTreePanel:
    def __init__(self):
        self.isActiveProject = False
        self.projectData = None
        self.root = None
        self.filter = None
        self.changeMgr = None
        self.tool = None
        self.plugin = None

    def set_project_data(self, project_name: str, project_data) -> None:
        if self.projectData is not None:
            self.projectData.remove_domain_folder_listener(self.change_mgr)
        self.projectData = project_data
        old_root = self.root
        self.root = create_root_node(project_name)
        tree.set_root_node(self.root)
        old_root.dispose()
        self.change_mgr = ChangeManager(self)
        self.projectData.add_domain_folder_listener(self.change_mgr)
        self.isActiveProject = self.projectData.get_root_folder().is_in_writable_project()
        tree.set_project_active(self.isActiveProject)

    def update_project_name(self, new_name: str) -> None:
        if isinstance(self.root, DomainFolderRootNode):
            ((DomainFolderRootNode) self.root).set_name(new_name)
        return

    # ... other methods ...

class ChangeManager:
    def __init__(self, panel):
        self.panel = panel
        return

    def notify_domain_change(self) -> None:
        if self.panel.plugin is not None:
            plugin_tool = self.panel.plugin.get_tool()
            plugin_tool.context_changed(None)
        return


# Inner Classes
class MyMouseListener(MouseAdapter):
    def mouse_pressed(self, event: MouseEvent) -> None:
        check_open(event)


class SelectDomainFilesTask(GTreeTask):
    def __init__(self, tree: GTree, files: set[DomainFile]) -> None:
        super().__init__(tree)
        self.files = files


    def run(self, monitor: TaskMonitor) -> None:
        do_select_domain_files(self.files)


# ... other methods ...

def create_root_node(project_name: str) -> GTreeNode:
    if project_data is not None:
        return DomainFolderRootNode(project_name, project_data.get_root_folder(), project_data, filter)
    else:
        return NoProjectNode()


def check_open(event: MouseEvent) -> None:
    if tool is None:  # dialog use
        return

    if event.button != MouseButton.BUTTON1 or event.click_count != 2:
        return

    event.consume()
    point = event.point
    path_for_location = tree.path_for_location(point.x, point.y)
    if path_for_location is None:
        return

    node = (GTreeNode) path_for_location.get_last_component()
    if not isinstance(node, DomainFileNode):
        return

    domain_file = ((DomainFileNode) node).get_domain_file()
    plugin.open_domain_file(domain_file)


def find_and_select(s: str) -> None:
    if project_data.file_count < MAX_PROJECT_SIZE_TO_SEARCH:
        tree.expand_tree(self.root)
        for it in self.root.iterator(True):
            node = it.next()
            if node.name == s:
                tree.set_selected_node(node)
                return
