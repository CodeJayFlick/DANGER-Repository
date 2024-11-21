Here is the equivalent Python code:

```Python
class Pixel:
    WHITE = (255, 255, 255)
    BLACK = (0, 0, 0)

class FrameBuffer:
    HEIGHT = 100
    WIDTH = 200

    def __init__(self):
        self.pixels = [[Pixel.WHITE for _ in range(FrameBuffer.WIDTH)] for _ in range(FrameBuffer.HEIGHT)]

    def clear_all(self):
        for row in self.pixels:
            for pixel in row:
                pixel = Pixel.WHITE

    def clear(self, x: int, y: int):
        if 0 <= x < FrameBuffer.WIDTH and 0 <= y < FrameBuffer.HEIGHT:
            self.pixels[y][x] = Pixel.WHITE

    def draw(self, x: int, y: int):
        if 0 <= x < FrameBuffer.WIDTH and 0 <= y < FrameBuffer.HEIGHT:
            self.pixels[y][x] = Pixel.BLACK

    def get_pixels(self):
        return [row[:] for row in self.pixels]

import unittest
from unittest.mock import patch

class TestFrameBuffer(unittest.TestCase):

    @patch('builtins.print')
    def test_clear_all(self, mock_print):
        frame_buffer = FrameBuffer()
        frame_buffer.clear_all()
        expected_output = [[Pixel.WHITE for _ in range(FrameBuffer.WIDTH)] for _ in range(FrameBuffer.HEIGHT)]
        self.assertEqual(frame_buffer.get_pixels(), expected_output)

    @patch('builtins.print')
    def test_clear(self, mock_print):
        frame_buffer = FrameBuffer()
        frame_buffer.pixels[0][0] = Pixel.BLACK
        frame_buffer.clear(0, 0)
        expected_output = [[Pixel.WHITE for _ in range(FrameBuffer.WIDTH)] for _ in range(FrameBuffer.HEIGHT)]
        self.assertEqual(frame_buffer.get_pixels(), expected_output)

    @patch('builtins.print')
    def test_draw(self, mock_print):
        frame_buffer = FrameBuffer()
        frame_buffer.draw(0, 0)
        expected_output = [[Pixel.WHITE for _ in range(FrameBuffer.WIDTH)]]
        expected_output[0][0] = Pixel.BLACK
        self.assertEqual(frame_buffer.get_pixels(), expected_output)

    @patch('builtins.print')
    def test_get_pixels(self, mock_print):
        frame_buffer = FrameBuffer()
        pixel_array = [[Pixel.WHITE for _ in range(FrameBuffer.WIDTH)] for _ in range(FrameBuffer.HEIGHT)]
        pixel_array[0][0] = Pixel.BLACK
        frame_buffer.pixels = pixel_array
        self.assertEqual(frame_buffer.get_pixels(), pixel_array)

if __name__ == '__main__':
    unittest.main()
```

This Python code defines the same classes and methods as your Java code, with some minor differences due to language-specific features. The test cases are also similar but use `unittest` module for unit testing in Python.