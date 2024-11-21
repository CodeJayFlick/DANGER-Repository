import logging

class Scene:
    def __init__(self):
        self.frame_buffers = [None] * 2
        for i in range(2):
            self.frame_buffers[i] = {'clear': lambda: None, 'draw': lambda x, y: None}
        self.current_buffer_index = 0
        self.next_buffer_index = 1

    def draw(self, coordinate_list):
        logging.info("Start drawing next frame")
        logging.info(f"Current buffer: {self.current_buffer_index}, Next buffer: {self.next_buffer_index}")
        for coord in coordinate_list:
            x, y = coord
            self.frame_buffers[self.next_buffer_index]['draw'](x, y)
        logging.info("Swap current and next buffer")
        self.swap()
        logging.info(f"Finish swapping. Current buffer: {self.current_buffer_index}, Next buffer: {self.next_buffer_index}")

    def get_current_buffer(self):
        logging.info(f"Get current buffer: {self.current_buffer_index}")
        return self.frame_buffers[self.current_buffer_index]

    def swap(self):
        self.current_buffer_index ^= self.next_buffer_index
        self.next_buffer_index = self.current_buffer_index ^ self.next_buffer_index
        self.current_buffer_index = self.current_buffer_index ^ self.next_buffer_index

# Usage:
scene = Scene()
coordinate_list = [(1, 2), (3, 4)]
scene.draw(coordinate_list)
print(scene.get_current_buffer())
