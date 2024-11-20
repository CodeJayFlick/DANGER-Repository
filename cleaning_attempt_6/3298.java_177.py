class GhidraToolStateFactory:
    def create_tool_state(self, tool: 'PluginTool', domain_object: 'DomainObject') -> 'GhidraToolState':
        return GhidraToolState(tool, domain_object)

# Note: In Python, we don't need an explicit `@Override` annotation
