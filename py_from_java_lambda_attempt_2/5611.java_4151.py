Here is the translation of the given Java code into Python:

```Python
class MemoryBlockMap:
    def __init__(self, program):
        self.program = program
        self.blocks = None
        self.pixels = None
        self.addresses_per_pixel = 0.0

    def create_mapping(self, width):
        if width <= 0:
            return
        
        blocks = self.program.get_memory().get_blocks()
        pixels = [0] * len(blocks)
        total_size = sum(block.size() for block in blocks)

        self.addresses_per_pixel = float(total_size) / float(width)
        
        for i, block in enumerate(blocks):
            pixels[i] = int(math.floor(block.size() / self.addresses_per_pixel))

    def get_address(self, pixel):
        if not self.pixels:
            return None

        try:
            current_position = 0
            for i, size in enumerate(self.pixels):
                if current_position + size > pixel:
                    start_address = blocks[i].get_start()
                    end_address = start_address.add(int(math.floor((pixel - current_position) * self.addresses_per_pixel)))
                    return end_address

                current_position += size
        except Exception as e:
            pass
        
        return None

    def get_pixel(self, address):
        if not (address and self.pixels and self.blocks):
            return -1

        for i, block in enumerate(self.blocks):
            if block.contains(address):
                offset = address.subtract(block.get_start())
                pixel = int(math.floor(offset / self.addresses_per_pixel)) + current_position
                return pixel
            
            current_position += size
        
        return -1

    def get_blocks(self):
        return self.blocks

    def get_block_position(self, block):
        x = 0
        for i in range(len(blocks)):
            if block == blocks[i]:
                return Rectangle(x, 0, pixels[i], 0)
            
            x += size
        
        return None

    def clear(self):
        self.blocks = None
        self.pixels = None