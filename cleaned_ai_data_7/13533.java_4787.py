# This plugin provides a test for circular dependencies in plugins.
class CircularPluginB:
    def __init__(self):
        pass  # No need for PluginTool here as it's not present in Python.

# Note: In Python, we don't have direct equivalents of Java annotations like @PluginInfo. 
# We can achieve similar functionality using docstrings or custom functions.
