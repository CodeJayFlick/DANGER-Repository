Here is the translation of the Java code into Python:

```Python
class AssemblyContextGraph:
    def __init__(self, lang, grammar):
        self.grammar = grammar
        self.lang = lang
        self.semantics = {}
        for rec in grammar.getPureRecursion():
            if rec:
                for sem in grammar.getSemantics(rec):
                    if not self.semantics.get(grammer.getStartName()):
                        self.semantics[grammar.getStartName()] = set()
                    self.semantics[grammar.getStartName()].add(sem)
        
    def gather_semantics(self):
        pass

    class Vertex:
        def __init__(self, context, subtable):
            self.context = context
            self.subtable = subtable
        
        def matches(self, that):
            if not self.subtable == that.subtable:
                return False
            if self.context.combine(that.context) is None:
                return False
            return True

    class Edge(GEdge[Vertex]):
        def __init__(self, sem, op, start, end):
            self.sem = sem
            self.op = op
            self.start = start
            self.end = end
        
        @property
        def get_start(self):
            return self.start
        
        @property
        def get_end(self):
            return self.end

    def compute_out_edges(self, from_vertex):
        if not from_vertex in self.cached_vertices:
            self.cached_vertices.add(from_vertex)
        
        result = set()
        for sem in self.semantics.get(from_vertex.subtable):
            for rc in sem.patterns:
                pattern = rc.ctx
                outer = from_vertex.context.combine(pattern)
                if outer is None:
                    continue
                
                orc = AssemblyResolution.context_only(outer, "For context transition", None)
                irc = sem.apply_forward(orc)
                inner = irc.get_context()
                
                for i in range(sem.constructor().get_num_operands()):
                    op = sem.constructor().get_operand(i)
                    def_symbol = op.get_defining_symbol()
                    if not isinstance(def_symbol, SubtableSymbol):
                        continue
                    
                    subtable = def_symbol
                    dest_vertex = Vertex(inner, subtable.name)
                    self.cached_vertices.add(dest_vertex)
                    
                    edge = Edge(sem, i, from_vertex, dest_vertex)
                    self.cached_edges.add(edge)
                    result.add(edge)

        return result

    @property
    def cached_out_edges(self):
        if not hasattr(self, 'cached_out_edges'):
            self.cached_out_edges = {}
        
        return self.cached_out_edges
    
    # This operation is not supported.
    def get_in_edges(self, v):
        raise UnsupportedOperationException("Does not support backward traversal")

    @property
    def cached_vertices(self):
        if not hasattr(self, 'cached_vertices'):
            self.cached_vertices = set()
        
        return self.cached_vertices

    @property
    def cached_edges(self):
        if not hasattr(self, 'cached_edges'):
            self.cached_edges = set()
        
        return self.cached_edges
    
    # Returns a copy of the graph explored so far.
    def copy(self):
        graph = GDirectedGraph()
        for v in self.cached_vertices:
            graph.add_vertex(v)
        for e in self.cached_edges:
            graph.add_edge(e)
        return graph
```

Note that this translation is not perfect, as some Java-specific constructs (like `GImplicitDirectedGraph`, `LazyMap`, etc.) do not have direct Python equivalents.