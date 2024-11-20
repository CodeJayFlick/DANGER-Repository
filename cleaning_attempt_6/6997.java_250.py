import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.framework.options import Options
from ghidra.framework.plugintool import PluginTool

class ToolPropertiesExampleScript(GhidraScript):
    def run(self) -> None:
        tool = self.state.get_tool()
        
        options = tool.get_options("name of my script")
        
        foo_string = options.get("foo", None)
        
        if foo_string is None:  # does not exist in tool options
            foo_string = input("Enter foo value: ")
            
            if foo_string:
                options.set("foo", foo_string)
                
        print(foo_string)

# Create an instance of the script and run it.
script = ToolPropertiesExampleScript()
try:
    script.run()
except Exception as e:
    print(f"An error occurred: {e}")
