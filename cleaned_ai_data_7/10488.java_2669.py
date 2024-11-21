class Dominator:
    def __init__(self):
        self.vertex_color = None
        self.calling_parent = None
        self.vertex_weight = None
        self.edge_weight = None
        self.vertex_type = None
        self.paths = []

    white = 0
    gray = 1

    def set_dominance(self, roots=None):
        if not isinstance(roots, list) or len(roots) > 1:
            return None
        
        v = roots[0]
        single_path = []
        
        while self.has_white_child(v) or v != roots[0]:
            v = self.add_to_paths(v, single_path)
            if single_path not in self.paths:
                self(paths).append(single_path)
                single_path = [x for x in single_path]
            
            self.whiten_children(v)
            v = self.back_track(v)
            single_path.pop()
        
        return self.get_dominance_graph()

    def get_dominance_graph(self):
        dom = Dominator()
        it = iter(self.vertices())
        
        if len(list(it)) == 1:
            dom.add(next(it))
            return dom
        
        for v in it:
            parent = self.get_dominator(v)
            dom.add(v)
            dom.add(parent)
            dom.add(Edge(parent, v))
        
        return dom

    def add_to_paths(self, v):
        i = len(self.paths[-1])
        self.set_color(v, 1)
        if not self.has_white_child(v) and self.get_calling_parent(v) != None:
            flag = True
        else:
            flag = False
        
        while self.has_white_child(v):
            next_v = self.go_to_next_white_child(v)
            self.set_color(next_v, 1)
            self.paths[-1].append(i + 1, v)
        
        return v

    def has_white_child(self, v):
        it = iter(self.children(v))
        flag = False
        for child in it:
            if self.get_color(child) == self.white:
                flag = True
        
        return flag

    def whiten_children(self, v):
        it = iter(self.children(v))
        while next(it):
            child = next(it)
            parent = self.get_calling_parent(child)
            if parent != None and parent == v:
                self.set_color(child, 0)

    # Other methods...
