class DataTypesActionContext:
    def __init__(self, provider, program, archive_gtree, clicked_node):
        self.clicked_node = clicked_node
        self.is_toolbar_action = False
        self.archive_gtree = archive_gtree
        super().__init__(provider, program)

    @property
    def is_toolbar_action(self):
        return self.is_toolbar_action

    @property
    def selected_node(self):
        return self.clicked_node

    def get_selected_files(self):
        if not hasattr(self, 'domain_files'):
            selection_paths = self.archive_gtree.get_selection_paths()
            domain_files = []
            for path in selection_paths:
                last_component = path[-1]
                if isinstance(last_component, ProjectArchiveNode):
                    node = last_component
                    archive = node.get_archive()
                    original_domain_file = archive.get_domain_file()
                    domain_files.append(original_domain_file)
        return getattr(self, 'domain_files', [])

    def get_file_count(self):
        return len(getattr(self, 'selected_files', []))

    @property
    def is_in_active_project(self):
        return True

class ProjectArchiveNode:
    pass

class DomainFile:
    pass

class ProgramActionContext:
    def __init__(self, provider, program):
        self.provider = provider
        self.program = program

    def __call__(self):
        # implement the method body here
        pass

class DataTypeArchiveGTree:
    def get_selection_paths(self):
        # implement this method to return a list of TreePath objects
        pass

# Example usage:
provider = 'your_provider_here'
program = 'your_program_here'
archive_gtree = DataTypeArchiveGTree()
clicked_node = ProjectArchiveNode()

context = DataTypesActionContext(provider, program, archive_gtree, clicked_node)
print(context.get_selected_files())
