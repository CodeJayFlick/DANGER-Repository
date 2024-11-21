Here is the translation of the Java code into Python:

```Python
class ToolManager:
    def __init__(self):
        self.project = None
        self.toolChest = None
        self.activeWorkspaceChanged = False
        self.inRestoreMode = False
        self.workspaces = []
        self.wsMap = {}
        self.connectMap = {}

    def registerTool(self, toolName: str, tool: 'PluginTool'):
        if not self.namesMap.get(toolName):
            self.namesMap[toolName] = [tool]
        else:
            self.namesMap[toolName].append(tool)

        if len(self.namesMap[toolName]) == 1:
            self.toolStatusMap[toolName] = ToolSaveStatus.AUTO_SAVE_MODE

    def deregisterTool(self, toolName: str, tool: 'PluginTool'):
        list_ = self.namesMap.get(toolName)
        if list_ and tool in list_:
            list_.remove(tool)

        if len(list_) == 0:
            del self.namesMap[toolName]
            del self.toolStatusMap[toolName]

    def getConnection(self, producer: 'PluginTool', consumer: 'PluginTool'):
        key = f"{producer.getName()}{consumer.getName()}"
        connection = self.connectMap.get(key)
        if not connection:
            connection = ToolConnection(producer, consumer)
            self.connectMap[key] = connection
        return connection

    def createWorkspace(self, name: str) -> 'Workspace':
        workspace = Workspace(name, self)
        self.workspaces.append(workspace)
        self.wsMap[name] = workspace
        if not self.activeWorkspace:
            self.setActiveWorkspace(workspace)

    def removeWorkspace(self, ws: 'Workspace'):
        for tool in ws.getTools():
            tool.close()

        self.workspaces.remove(ws)
        del self.wsMap[ws.getName()]

    def getWorkspaces(self) -> list['Workspace']:
        return self.workspaces

    # ... other methods ...
```

Note that this translation is not perfect, as Python and Java have different syntaxes. Some parts of the code may need to be adjusted or re-written in order for it to work correctly in a Python environment.

Also note that I used type hints (e.g., `-> 'Workspace'`) which are available since Python 3.5. If you're using an earlier version, these will not be recognized by your IDE and should be removed.