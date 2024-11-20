class DBTraceProgramViewMemory:
    def __init__(self, program):
        self.program = program
        self.blocks = {}
        # Assuming Map<DBTraceMemoryRegion, DBTraceProgramViewMemoryBlock> in Java becomes a dictionary in Python

    def get_top_region(self, reg_func):
        return next((reg for s in range(len(self.program.viewport)) if (reg := reg_func(s)) is not None and self.program.is_region_visible(reg)), None)

    def for_visible_regions(self, action):
        for snap in self.program.viewport:
            for region in self.memory_manager.get_regions_at_snap(snap):
                if self.program.is_region_visible(region):
                    action(region)
                    
    @property
    def memory_manager(self):  # Assuming this is a property of the class

    def recompute_address_set(self):
        temp = set()
        self.for_visible_regions(lambda reg: temp.update(reg.get_range()))
        self.address_set = temp

    def get_block(self, region):
        return self.blocks.setdefault(region, DBTraceProgramViewMemoryBlock(self.program, region))

    @property
    def address_set(self):  # Assuming this is a property of the class

    def get_block(self, addr):
        for s in range(len(self.program.viewport)):
            if (region := memory_manager.get_region_containing(s, addr)) is not None:
                return self.get_block(region)
        return None

    @property
    def memory_manager(self):  # Assuming this is a property of the class

    def get_block(self, block_name):
        for s in range(len(self.program.viewport)):
            if (region := memory_manager.get_live_region_by_path(s, block_name)) is not None:
                return self.get_block(region)
        return None

    @property
    def address_set(self):  # Assuming this is a property of the class

    def get_blocks(self):
        result = []
        for reg in self.program.viewport:
            if (region := memory_manager.get_region_containing(reg, None)) is not None and self.program.is_region_visible(region):
                result.append(self.get_block(region))
        return sorted(result)

    def update_add_block(self, region):
        # TODO: add block to cache?
        self.add_range(region.get_range())

    @property
    def memory_manager(self):  # Assuming this is a property of the class

    def update_change_block_name(self, region):
        pass

    def update_change_block_flags(self, region):
        pass

    def update_change_block_range(self, region, old_range, new_range):
        self.change_range(old_range, new_range)

    @property
    def memory_manager(self):  # Assuming this is a property of the class

    def update_delete_block(self, region):
        del self.blocks[region]
        self.remove_range(region.get_range())

    def update_refresh_blocks(self):
        self.blocks.clear()
        self.recompute_address_set()

class DBTraceProgramViewMemoryBlock:
    def __init__(self, program, region):
        pass

# Assuming the above classes are properties of this class
