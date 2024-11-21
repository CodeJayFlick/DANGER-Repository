Here is the translation of the given Java code into equivalent Python:

```Python
class LayoutFunction:
    def __init__(self):
        pass

    def apply(self, name: str) -> callable:
        if name == "GEM":
            return GEMLayoutAlgorithm.edge_aware_builder()
        elif name == "FORCED_BALANCED":
            return KKLayoutAlgorithm.builder().pre_relax_duration(1000)
        elif name == "FORCE_DIRECTED":
            return FRLayoutAlgorithm.builder().repulsion_contract(BarnesHutFRRepulsion())
        elif name == "CIRCLE":
            return CircleLayoutAlgorithm.builder().reduce_edge_crossing(False)
        elif name == "COMPACT_RADIAL":
            return TidierRadialTreeLayoutAlgorithm.edge_aware_builder(edge_comparator=self.edge_type_comparator)
        elif name == "MIN_CROSS_TOP_DOWN" or name == "VERT_MIN_CROSS_TOP_DOWN":
            return EiglspergerLayoutAlgorithm.edge_aware_builder(
                edge_comparator=self.edge_type_comparator, layering=Layering.TOP_DOWN
            )
        elif name == "MIN_CROSS_LONGEST_PATH" or name == "VERT_MIN_CROSS_LONGEST_PATH":
            return EiglspergerLayoutAlgorithm.edge_aware_builder(
                edge_comparator=self.edge_type_comparator, layering=Layering.LONGEST_PATH
            )
        elif name == "MIN_CROSS_NETWORK_SIMPLEX" or name == "VERT_MIN_CROSS_NETWORK_SIMPLEX":
            return EiglspergerLayoutAlgorithm.edge_aware_builder(
                edge_comparator=self.edge_type_comparator, layering=Layering.NETWORK_SIMPLEX
            )
        elif name == "MIN_CROSS_COFFMAN_GRAHAM" or name == "VERT_MIN_CROSS_COFFMAN_GRAHAM":
            return EiglspergerLayoutAlgorithm.edge_aware_builder(
                edge_comparator=self.edge_type_comparator, layering=Layering.COFFMAN_GRAHAM
            )
        elif name == "RADIAL":
            return RadialTreeLayoutAlgorithm.builder().vertical_vertex_spacing(300)
        elif name == "BALLOON":
            return BalloonLayoutAlgorithm.builder().vertical_vertex_spacing(300)
        elif name == "HIERACHICAL":
            return EdgeAwareTreeLayoutAlgorithm.edge_aware_builder()
        elif name == "COMPACT_HIERARCHICAL":
            return TidierTreeLayoutAlgorithm.edge_aware_builder(edge_comparator=self.edge_type_comparator)

    @property
    def edge_type_comparator(self) -> callable:
        pass

# Usage example:

lf = LayoutFunction()

layout_algorithm = lf.apply("GEM")
```

Please note that this translation is not a direct conversion from Java to Python. The code has been rewritten in Python style, and some parts have been modified or simplified for better readability and maintainability.

Also, the `Objects` class used in the original Java code does not exist in Python, so it was removed.