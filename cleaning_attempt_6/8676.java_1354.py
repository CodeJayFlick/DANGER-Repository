class BlockModelGraphDisplayListener:
    def __init__(self, tool, block_model, graph_display):
        self.block_model = block_model
        super().__init__(tool, block_model.get_program(), graph_display)

    def get_address(self, vertex):
        return super().get_address(vertex)

    def get_vertex_id(self, address):
        try:
            blocks = self.block_model.get_code_blocks_containing(address)
            if blocks and len(blocks) > 0:
                return super().get_vertex_id(blocks[0].first_start_address())
        except CancelledException:
            pass
        return super().get_vertex_id(address)

    def get_vertices(self, addr_set):
        vertices = set()
        try:
            self.add_vertices_for_addresses(addr_set, vertices)
        except CancelledException:
            pass
        return vertices

    def add_vertices_for_addresses(self, addr_set, vertices):
        sym_table = self.block_model.get_program().get_symbol_table()
        for block in self.block_model.get_code_blocks_containing(addr_set):
            start_addr = block.first_start_address()
            if start_addr.is_external_address():
                symbol = sym_table.get_primary_symbol(start_addr)
                addr_string = symbol.name(True)
            else:
                addr_string = str(start_addr)
            vertex = graph_display.graph().get_vertex(addr_string)
            if vertex is not None:
                vertices.add(vertex)

    def get_addresses(self, vertices):
        addr_set = set()
        for vertex in vertices:
            self.add_block_addresses(addr_set, vertex)
        return addr_set

    def add_block_addresses(self, addr_set, vertex):
        block_addr = self.get_address(vertex)
        if not self.is_valid_address(block_addr):
            return
        blocks = None
        if self.block_model is not None:
            block = self.block_model.code_block_at(block_addr)
            if block is not None:
                blocks = [block]
            else:
                blocks = self.block_model.get_code_blocks_containing(block_addr)
        if blocks and len(blocks) > 0:
            for block in blocks:
                addr_set.add(block)
        else:
            addr_set.update(range(block_addr, block_addr + 1))

    def is_valid_address(self, address):
        return (address is not None and self.block_model.get_program() is not None
                and self.block_model.get_program().get_memory().contains(address) or address.is_external_address())

    def clone_with(self, new_graph_display):
        return BlockModelGraphDisplayListener(self.tool, self.block_model, new_graph_display)
