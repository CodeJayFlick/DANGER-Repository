import ghidra_framework as gh

class ToolStateFactory:
    @classmethod
    def register(cls):
        gh.PluggableServiceRegistry.register_service(cls)

    @classmethod
    def create_tool_state(cls, tool: 'PluginTool', domain_object: 'DomainObject') -> 'ToolState':
        factory = gh.PluggableServiceRegistry.get_service(ToolStateFactory)
        return factory.do_create_tool_state(tool, domain_object)

    def do_create_tool_state(self, tool: 'PluginTool', domain_object: 'DomainObject') -> 'ToolState':
        return ToolState(tool, domain_object)


class ToolState:
    def __init__(self, tool: 'PluginTool', domain_object: 'DomainObject'):
        self.tool = tool
        self.domain_object = domain_object

# Register the factory when this file is imported
if not hasattr(ToolStateFactory, '__initialized__'):
    ToolStateFactory.register()
