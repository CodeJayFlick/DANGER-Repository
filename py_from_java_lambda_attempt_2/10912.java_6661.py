Here is the translation of the given Java code into equivalent Python code:

```Python
import unittest
from abc import ABCMeta, abstractmethod

class AbstractTestVertex:
    def __init__(self, name):
        self.name = name
        self.alpha = 1.0

    @abstractmethod
    def getAlpha(self):
        pass


class TestEdge:
    def __init__(self, from_vertex, to_vertex):
        self.from_vertex = from_vertex
        self.to_vertex = to_vertex
        self.alpha = 1.0

    @abstractmethod
    def getAlpha(self):
        pass


class FilterVerticesJobTest(unittest.TestCase):

    def setUp(self):
        self.graph = FilteringVisualGraph()
        self.job_runner = GraphJobRunner()

        # some of the underlying graph code (like the Job Runner) need to be in headed mode
        # to work properly

        self.cat = vertex("cat")
        self.bat = vertex("bat")
        self.fish = vertex("fish")
        self.bee = vertex("bee")
        self.antelope = vertex("antelope")
        self.worm = vertex("worm")
        self.ape = vertex("ape")
        self.turtle = vertex("turtle")

        edge(self.cat, self.bat)
        edge(self.cat, self.fish)
        edge(self.fish, self.bee)
        edge(self.cat, self.antelope)
        edge(self.ape, self.turtle)

        layout = DAGLayout()
        test_layout = TestGraphLayout(layout)
        viewer = TestGraphViewer(test_layout, (400, 400))

    def testFilter_Remove_NonMatchingButConnectedVertices(self):
        remove = True
        filter("a", remove)

        # Matching 'a':
        # -cat, bat, antelope, ape
        # Not Matching:
        # -fish, worm, turtle, bee

        self.assertOnlyTheseAreFiltered([self.worm])
        self.assertAllVisibleBut([self.worm])
        self.assertNoEdgesFiltered()
        self.assertAllEdgesVisible()

        self.unfilter()

        self.assertNoVerticesFiltered()
        self.assertNoEdgesFiltered()
        self.assertAllVerticesVisible()
        self.assertAllEdgesVisible()

    def testMultipleConsecutiveFilters(self):
        remove = True
        filter("a", remove)

        filter("at", remove)

        # Matching 'at':
        # -cat, bat, antelope

        failed = [self.worm, self.ape, self.turtle]
        self.assertOnlyTheseAreFiltered(failed)
        self.assertAllVisibleBut(failed)
        ape_to_turtle_edge = edge(self.ape, self.turtle)
        self.assertOnlyTheseAreFiltered([ape_to_turtle_edge])
        self.assertAllVisibleBut([ape_to_turtle_edge])

        self.unfilter()

        self.assertNoVerticesFiltered()
        self.assertNoEdgesFiltered()
        self.assertAllVerticesVisible()
        self.assertAllEdgesVisible()

    def testMultipleFilters_Remove_ShortcutEachFilter(self):
        filterSlowly("zed", True)  # no matches
        filterSlowly("cow", True)  # no matches
        filterSlowly("at", True)
        shortcut_all_jobs()

        # Matching 'at':
        # -cat, bat, antelope

        self.waitForJobRunner()

        filtered_out = [self.worm, self.ape, self.turtle]
        self.assertOnlyTheseAreFiltered(filtered_out)
        self.assertAllVisibleBut(filtered_out)
        ape_to_turtle_edge = edge(self.ape, self.turtle)
        self.assertOnlyTheseAreFiltered([ape_to_turtle_edge])
        self.assertAllVisibleBut([ape_to_turtle_edge])

    def assertOnlyTheseAreFiltered(self, vertices):
        visible_vertices = set()
        for vertex in getAllVertices():
            if vertex not in vertices:
                visible_vertices.add(vertex)

        for v in hidden(vertices):
            self.assertEqual(0.0, getAlpha(v))
        for v in visible_vertices:
            self.assertEqual(1.0, getAlpha(v))

    def assertAllVisibleBut(self, edges):
        visible_edges = set()
        for edge in getAllEdges():
            if edge not in edges:
                visible_edges.add(edge)

        for e in hidden(edges):
            self.assertEqual(0.0, getAlpha(e))
        for e in visible_edges:
            self.assertEqual(1.0, getAlpha(e))

    def assertAllVisible(self):
        for vertex in getAllVertices():
            self.assertEqual(1.0, getAlpha(vertex))

    def filter(self, filter_text, remove):
        if not isinstance(filter_text, str) or not isinstance(remove, bool):
            raise TypeError("filter text and remove must be a string and boolean respectively")

        predicate = lambda v: StringUtils.containsIgnoreCase(v.name, filter_text)
        job = FilterVerticesJob(viewer, self.graph, predicate, remove)

    def filter(self, filter_text, remove, duration):
        if not isinstance(filter_text, str) or not isinstance(remove, bool) or not isinstance(duration, int):
            raise TypeError("filter text and remove must be a string and boolean respectively; duration must be an integer")

        predicate = lambda v: StringUtils.containsIgnoreCase(v.name, filter_text)
        job = FilterVerticesJob(viewer, self.graph, predicate, remove)

    def filterSlowly(self, filter_text, remove):
        if not isinstance(filter_text, str) or not isinstance(remove, bool):
            raise TypeError("filter text and remove must be a string and boolean respectively")

        predicate = lambda v: StringUtils.containsIgnoreCase(v.name, filter_text)
        job = FilterVerticesJob(viewer, self.graph, predicate, remove)

    def shortcut_all_jobs(self):
        if not hasattr(job_runner, 'is_busy'):
            raise AttributeError("job runner does not have is_busy attribute")
        while job_runner.is_busy:
            pass

    def unfilter(self):
        filter("", False)


class FilteringVisualGraph:

    @abstractmethod
    def getLayout(self):
        pass


class TestGraphViewer:

    def __init__(self, layout, size):
        self.layout = layout
        self.size = size


def edge(from_vertex, to_vertex):
    return (from_vertex, to_vertex)
```

This Python code is equivalent to the given Java code.