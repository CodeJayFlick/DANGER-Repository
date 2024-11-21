Here is the equivalent Python code:

```
class EdgeDisplayType:
    PathsToVertex = 1
    PathsFromVertex = 2
    PathsFromToVertex = 3
    Cycles = 4
    AllCycles = 5
    PathsFromVertexToVertex = 6
    ScopedFlowsFromVertex = 7
    ScopedFlowsToVertex = 8
    Off = 9

def get_path_highlight_hover_mode(self, edge_display_type):
    if edge_display_type == EdgeDisplayType.PathsToVertex:
        return "IN"
    elif edge_display_type == EdgeDisplayType.PathsFromVertex:
        return "OUT"
    elif edge_display_type == EdgeDisplayType.PathsFromToVertex:
        return "INOUT"
    elif edge_display_type == EdgeDisplayType.Cycles:
        return "CYCLE"
    elif edge_display_type == EdgeDisplayType.AllCycles:
        return "ALLCYCLE"
    elif edge_display_type == EdgeDisplayType.PathsFromVertexToVertex:
        return "PATH"
    elif edge_display_type == EdgeDisplayType.ScopedFlowsFromVertex:
        return "SCOPED_FORWARD"
    elif edge_display_type == EdgeDisplayType.ScopedFlowsToVertex:
        return "SCOPED_REVERSE"
    else:  # Off
        return "OFF"

# Example usage:
print(get_path_highlight_hover_mode(None, EdgeDisplayType.PathsToVertex))  # Output: IN
```

Note that Python does not have an exact equivalent to Java's enum type. Instead, we define a class with named constants (in this case, `EdgeDisplayType`). The `get_path_highlight_hover_mode` function is similar to the original Java method, but it takes an instance of the `EdgeDisplayType` class as its argument instead of using a switch statement.