Here is a translation of the Java code into equivalent Python:

```Python
class GraphASTControlFlowAction:
    def __init__(self):
        self.name = "Graph AST Control Flow"
        self.help_location = HelpLocation(HelpTopics.DECOMPILER, "ToolBarGraph")
        self.menu_bar_data = MenuData(["Graph AST Control Flow"], "graph")

    def is_enabled_for_decompiler_context(self, context):
        return context.function is not None

    def decompiler_action_performed(self, context):
        tool = context.tool
        graph_display_broker_service = tool.get_service(GraphDisplayBroker)
        if graph_display_broker_service is None:
            Msg.show_error(self, tool.frame, "AST Graph Failed", 
                           "Graph consumer not found: Please add a graph consumer provider to your tool")
            return

        options = tool.options["Graph"]
        reuse_graph = options.getboolean("Reuse Graph", False)
        code_limit_per_block = options.getint("Max Code Lines Displayed", 10)
        high_function = context.high_function
        location_addr = context.location.address
        task = ASTGraphTask(graph_display_broker_service, not reuse_graph, 
                             code_limit_per_block, location_addr, high_function,
                             CONTROL_FLOW_GRAPH, tool)
        TaskLauncher(task, tool.frame).start()
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the concept of classes and objects is different in both languages.