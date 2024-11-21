class BlockInventoryHolder:
    def __init__(self, block_state):
        super().__init__(block_state, False)

    def get_inventory(self):
        return (getattr(block_state, 'get_inventory')).()
