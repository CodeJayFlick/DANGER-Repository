class VersionControlShowHistoryAction:
    def __init__(self):
        self.plugin = None  # This should be set when creating an instance of this class.

    def get_plugin(self):
        return self.plugin

    def set_plugin(self, plugin):
        self.plugin = plugin

    def get_name(self):
        if not hasattr(self, 'name'):
            raise ValueError("Name has to be set before calling this method.")
        return self.name

    def set_name(self, name):
        self.name = name

    def get_tool(self):
        if not hasattr(self, 'tool'):
            raise ValueError("Tool has to be set before calling this method.")
        return self.tool

    def set_tool(self, tool):
        self.tool = tool

    def is_enabled(self):
        return False  # This should be implemented based on the context.

    def perform_action(self, domain_file_context):
        if not hasattr(domain_file_context, 'get_selected_files'):
            raise ValueError("DomainFileContext has to have a get_selected_files method.")
        selected_files = domain_file_context.get_selected_files()
        self.show_history(selected_files)

    def show_history(self, domain_files):
        # This should be implemented based on the context.
        pass

class DomainFile:
    def __init__(self):
        self.is_versioned = False  # This should be set when creating an instance of this class.

    def is_versioned(self):
        return self.is_versioned
