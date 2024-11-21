Here is the translation of the Java code into Python:

```Python
class DisplayFilteredGraphAction:
    def __init__(self, tool, owner, provider):
        self.graphBroker = None
        super().__init__("DisplayFilteredGraph", tool, owner, provider)
        path = ["Display filtered...", "Graph"]
        icon = ResourceManager.load_image("images/breakpoints.png")
        set_popup_menu_data(MenuData(path, icon))
        key_binding_data = KeyBindingData(KeyEvent.VK_G,
                                            InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)
        self.set_key_binding_data(key_binding_data)
        help_location = HelpLocation(owner, "display_filtered_graph")
        self.set_help_location(help_location)
        provider.add_local_action(self)

    def do_action(self, container, path):
        if not self.graphBroker:
            Msg.show_error("GraphBroker not found: Please add a graph provider to your tool", self.tool.get_tool_frame())
            return
        clone = ObjectContainer.clone(container).set_immutable(True)
        get_offspring(clone, path)

    def graph_container(self, container, graph, start):
        children = container.current_children()
        for child in children:
            end = graph.add_vertex(child.name(), str(child))
            graph.add_edge(start, end, child.target_object().name())
            if child.has_elements():
                self.graph_container(child, graph, end)

    def finish_get_offspring(self, container, path):
        graph_provider = self.graphBroker.get_default_graph_display_provider()
        graph = AttributedGraph(container.name(), EmptyGraphType())
        start = graph.add_vertex(container.name(), str(container))
        self.graph_container(container, graph, start)
        try:
            graph_display = graph_provider.get_graph_display(True, TaskMonitor.DUMMY)
            graph_display.set_graph(graph, container.name(), False, TaskMonitor.DUMMY)
        except GraphException as e:
            print(e.stacktrace())
        except CancelledException:
            pass
```

Please note that this is a direct translation of the Java code into Python. However, it's not necessarily idiomatic or efficient Python code.