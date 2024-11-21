import ghidra_app

class SampleSearchTablePlugin:
    def __init__(self):
        self.provider = None

    def create_actions(self):
        action = {
            'name': "Search Stuff",
            'description': self.get_name(),
            'perform_action': lambda: self.search()
        }
        if current_program is not None:
            ghidra_app.add_docking_action(action)

    def dispose(self):
        if self.provider is not None:
            self.provider.dispose()

    def search(self):
        searcher = SampleSearcher(current_program)
        provider = SampleSearchTableProvider(self, searcher)
        ghidra_app.set_component_provider(provider, True)


class SampleSearcher:
    def __init__(self, program):
        pass


class SampleSearchTableProvider:
    def __init__(self, plugin, searcher):
        self.plugin = plugin
        self.searcher = searcher

    def dispose(self):
        # implement disposal logic here
        pass
