class JgtGraphMouse:
    def __init__(self, graph_display: 'DefaultGraphDisplay', allow_edge_selection: bool):
        self.graph_display = graph_display
        self.allow_edge_selection = allow_edge_selection

    def load_plugins(self) -> None:
        # edge 
        plugins = [
            JgtEdgeNavigationPlugin(InputEvent.BUTTON1_DOWN_MASK),
            JgtVertexFocusingPlugin(InputEvent.BUTTON1_DOWN_MASK, self.graph_display)
        ]

        if self.allow_edge_selection:
            plugins.append(SelectingGraphMousePlugin())
        else:
            plugins.append(VertexSelectingGraphMousePlugin())

        plugins.extend([
            RegionSelectingGraphMousePlugin(),
            TranslatingGraphMousePlugin(translating_mask=InputEvent.BUTTON1_DOWN_MASK),
            ScalingGraphMousePlugin(),
            JgtCursorRestoringPlugin()
        ])

    def allows_edge_selection(self) -> bool:
        return self.allow_edge_selection


class DefaultGraphDisplay:  # This class is not defined in the original code, but it's assumed to be a custom class
    pass

class AttributedVertex:  # This class is not defined in the original code, but it's assumed to be a custom class
    pass

class AttributedEdge:  # This class is not defined in the original code, but it's assumed to be a custom class
    pass


# Custom plugins
class JgtEdgeNavigationPlugin:
    def __init__(self, mask):
        self.mask = mask

class JgtVertexFocusingPlugin:
    def __init__(self, mask: int, graph_display: 'DefaultGraphDisplay'):
        self.mask = mask
        self.graph_display = graph_display

class SelectingGraphMousePlugin:
    pass

class VertexSelectingGraphMousePlugin:
    pass

class RegionSelectingGraphMousePlugin:
    pass

class TranslatingGraphMousePlugin:
    def __init__(self, translating_mask: int):
        self.translating_mask = translating_mask

class ScalingGraphMousePlugin:
    pass

class JgtCursorRestoringPlugin:
    pass
