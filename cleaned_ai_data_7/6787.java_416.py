import collections

class GraphASTAndFlow:
    def build_graph(self):
        vertices = {}
        op_iter = self.get_pcode_op_iterator()
        vertex_map = {}

        while op_iter.has_next():
            op = op_iter.next()
            o = self.create_op_vertex(op)
            vertex_map[op] = o
            for i in range(op.num_inputs()):
                if (i == 0 and 
                    (op.opcode() == PcodeOp.LOAD or op.opcode() == PcodeOp.STORE)):
                    continue

                if (i == 1 and op.opcode() == PcodeOp.INDIRECT):
                    continue
                
                vn = op.input(i)
                if vn is not None:
                    v = self.get_varnode_vertex(vertices, vn)
                    self.create_edge(v, o)

            out_vn = op.output()
            if out_vn is not None:
                out_v = self.get_varnode_vertex(vertices, out_vn)
                if out_v is not None:
                    self.create_edge(o, out_v)

        op_iter = self.get_pcode_op_iterator()
        seen_parents = set()

        first_map = {}
        last_map = {}

        while op_iter.has_next():
            op = op_iter.next()
            parent = op.parent
            if parent in seen_parents:
                continue

            iterator = parent.iterator()
            prev = None
            next = None
            
            while iterator.has_next():
                next = iterator.next()
                if prev is None and vertex_map.get(next):
                    first_map[parent] = vertex_map[next]
                
                if prev is not None and vertex_map.get(prev) and vertex_map.get(next):
                    edge = self.create_edge(vertex_map[prev], vertex_map[next])
                    edge.set_edge_type('WITHIN_BLOCK')
                    
                prev = next
            
            if next is not None and vertex_map.get(next):
                last_map[parent] = vertex_map[next]
            
            seen_parents.add(parent)

        key_set = first_map.keys()
        
        for block in key_set:
            for i in range(block.in_size()):
                in_block = block.get_in(i)
                if last_map.get(in_block):
                    edge = self.create_edge(last_map[in_block], first_map[block])
                    edge.set_edge_type('BETWEEN_BLOCK')
                    
