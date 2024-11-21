import logging

class App:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler = logging.FileHandler('app.log')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def main(self):
        scene = Scene()
        draw_pixels1 = [(1, 1), (5, 6), (3, 2)]
        scene.draw(draw_pixels1)
        buffer1 = scene.get_buffer()
        print_black_pixel_coordinate(buffer1)

        draw_pixels2 = [(3, 7), (6, 1)]
        scene.draw(draw_pixels2)
        buffer2 = scene.get_buffer()
        print_black_pixel_coordinate(buffer2)


    def print_black_pixel_coordinate(self, buffer):
        log = "Black Pixels: "
        pixels = buffer.get_pixels()
        for i in range(len(pixels)):
            if pixels[i] == Pixel.BLACK:
                y = i // FrameBuffer.WIDTH
                x = i % FrameBuffer.WIDTH
                log += f" ({x}, {y})"
        self.logger.info(log)


class Scene:
    def __init__(self):
        pass

    def draw(self, draw_pixels):
        pass

    def get_buffer(self):
        return None


class Pixel:
    BLACK = 0


class FrameBuffer:
    WIDTH = 10
