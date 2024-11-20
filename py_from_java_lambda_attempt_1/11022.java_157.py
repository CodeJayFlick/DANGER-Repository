Here is the translation of the Java code to Python:
```
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
```
Note that I've used type hints to indicate the expected types of the `tool` and `domain_object` parameters. This is a Python 3.5+ feature.

Also, I've assumed that `ghidra_framework` is an imported module or package that provides the necessary classes and functions for this code to work. You may need to modify the import statement accordingly.