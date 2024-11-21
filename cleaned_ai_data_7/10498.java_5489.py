class VertexSet:
    def __init__(self, parent_graph, capacity):
        self.parent_graph = parent_graph
        self.modification_number = 0
        self.capacity = max(capacity, 10)
        self.key_indices = {}
        self.first_outgoing_edge = [None] * self.capacity
        self.first_incoming_edge = [None] * self.capacity
        self.last_outgoing_edge = [None] * self.capacity
        self.last_incoming_edge = [None] * self.capacity
        self.vertices = [None] * self.capacity

    def index(self, v):
        try:
            return self.key_indices[v.key()]
        except KeyError:
            return -1

    def add(self, v):
        if not self.key_indices.get(v.key()):
            if len(self.vertices) >= self.capacity:
                self.grow()
            self.key_indices[v.key()] = len(self.vertices)
            self.vertices.append(v)
            self.modification_number += 1
            return True
        return False

    def remove(self, v):
        if not self.contains(v):
            return False
        index = self.index(v)
        while self.first_outgoing_edge[index] is not None:
            self.parent_graph.remove(self.first_outgoing_edge[index])
        while self.first_incoming_edge[index] is not None:
            self.parent_graph.remove(self.first_incoming_edge[index])
        del self.key_indices[v.key()]
        self.vertices[index] = None
        self.modification_number += 1
        return True

    def contains(self, v):
        if v is None:
            return False
        return self.key_indices.get(v.key())

    def get_by_index(self, index):
        return self.vertices[index]

    def num_sources(self):
        count = 0
        for i in range(len(self.vertices)):
            if not self.first_incoming_edge[i] and self.vertices[i]:
                count += 1
        return count

    def num_sinks(self):
        count = 0
        for i in range(len(self.vertices)):
            if not self.first_outgoing_edge[i] and self.vertices[i]:
                count += 1
        return count

    def get_sources(self):
        sources = []
        for i, v in enumerate(self.vertices):
            if not self.first_incoming_edge[i] and v:
                sources.append(v)
        return sources

    def get_sinks(self):
        sinks = []
        for i, v in enumerate(self.vertices):
            if not self.first_outgoing_edge[i] and v:
                sinks.append(v)
        return sinks

    def set_first_outgoing_edge(self, v, e):
        try:
            index = self.index(v)
            self.first_outgoing_edge[index] = e
        except KeyError:
            pass

    def set_last_outgoing_edge(self, v, e):
        try:
            index = self.index(v)
            self.last_outgoing_edge[index] = e
        except KeyError:
            pass

    def set_first_incoming_edge(self, v, e):
        try:
            index = self.index(v)
            self.first_incoming_edge[index] = e
        except KeyError:
            pass

    def set_last_incoming_edge(self, v, e):
        try:
            index = self.index(v)
            self.last_incoming_edge[index] = e
        except KeyError:
            pass

    def clear(self):
        if len(self.vertices) > 0:
            for i in range(len(self.vertices)):
                self.first_outgoing_edge[i] = None
                self.first_incoming_edge[i] = None
                self.last_outgoing_edge[i] = None
                self.last_incoming_edge[i] = None
            del self.key_indices

    def get_modification_number(self):
        return self.modification_number

    def grow(self):
        if len(self.vertices) * 13 > self.capacity * 9:
            new_capacity = int(len(self.vertices) * 1.7 + 7)
            new_vertices = [None] * new_capacity
            new_first_outgoing_edge = [None] * new_capacity
            new_first_incoming_edge = [None] * new_capacity
            new_last_outgoing_edge = [None] * new_capacity
            new_last_incoming_edge = [None] * new_capacity

            for i in range(len(self.vertices)):
                if self.vertices[i]:
                    index = len(new_vertices)
                    new_vertices[index] = self.vertices[i]
                    new_first_outgoing_edge[index] = self.first_outgoing_edge[i]
                    new_first_incoming_edge[index] = self.first_incoming_edge[i]
                    new_last_outgoing_edge[index] = self.last_outgoing_edge[i]
                    new_last_incoming_edge[index] = self.last_incoming_edge[i]

            del self.key_indices
            self.capacity = new_capacity
            self.vertices = new_vertices
            self.first_outgoing_edge = new_first_outgoing_edge
            self.first_incoming_edge = new_first_incoming_edge
            self.last_outgoing_edge = new_last_outgoing_edge
            self.last_incoming_edge = new_last_incoming_edge

    def tighten(self):
        for i in range(len(self.vertices)):
            if self.vertices[i]:
                index = len(new_vertices)
                new_vertices[index] = self.vertices[i]
                new_first_outgoing_edge[index] = self.first_outgoing_edge[i]
                new_first_incoming_edge[index] = self.first_incoming_edge[i]
                new_last_outgoing_edge[index] = self.last_outgoing_edge[i]
                new_last_incoming_edge[index] = self.last_incing_edge[i]

    def to_set(self):
        return set([v for v in self.vertices if v])

    def __str__(self):
        return str([v for v in self.vertices if v])
