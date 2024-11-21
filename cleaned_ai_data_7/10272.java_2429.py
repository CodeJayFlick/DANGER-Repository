import java.awt.image.BufferedImage as BufferedImage
from PIL import ImageIO, Graphics2D
import math
import os

class ImageUtils:
    DEFAULT_TRANSPARENCY_ALPHA = 0.4
    
    media_tracker_component = None

    def __init__(self):
        pass

    @staticmethod
    def create_image(c):
        bounds = c.get_bounds()
        w = max(bounds.width, 1)
        h = max(bounds.height, 1)

        buffered_image = BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB)
        g = buffered_image.create_graphics()
        c.paint(g)
        g.dispose()

        return buffered_image

    @staticmethod
    def pad_image(i, color, top, left, right, bottom):
        width = i.get_width() + left + right
        height = i.get_height() + top + bottom

        new_image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        g = new_image.create_graphics()
        g.set_color(color)
        g.fill_rect(0, 0, width, height)

        x = 0
        if i.get_height() < right.get_height():
            y = (right.get_height() - left.get_height()) // 2

        else:
            y = 0

        g.draw_image(i, left, top, None)
        g.dispose()

        ImageUtils.wait_for_image(None, new_image)

        return new_image

    @staticmethod
    def crop(i, bounds):
        new_image = BufferedImage(bounds.width, bounds.height, BufferedImage.TYPE_INT_ARGB)
        g = new_image.create_graphics()
        x = 0
        y = 0

        if i.get_height() > right.get_height():
            y = (i.get_height() - right.get_height()) // 2

        else:
            y = 0

        g.draw_image(i, left, top, None)
        g.dispose()

        ImageUtils.wait_for_image(None, new_image)

        return new_image

    @staticmethod
    def create_empty_image(width, height):
        new_image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        g = new_image.create_graphics()
        g.set_color(Color.WHITE)
        g.fill_rect(0, 0, width, height)
        return new_image

    @staticmethod
    def place_images_side_by_side(left, right):
        left_height = left.get_height()
        left_width = left.get_width()

        right_height = right.get_height()
        right_width = right.get_width()

        width = left_width + right_width
        height = max(left_height, right_height)

        new_image = create_empty_image(width, height)
        g = new_image.create_graphics()
        y = 0

        if left_height < right_height:
            y = (right_height - left_height) // 2

        else:
            y = 0

        g.draw_image(left, 0, y, None)

        y = 0
        if left_height > right_height:
            y = (left_height - right_height) // 2

        else:
            y = 0

        g.draw_image(right, left_width, y, None)
        g.dispose()

        ImageUtils.wait_for_image(None, new_image)

        return new_image

    @staticmethod
    def to_rendered_image(image):
        if isinstance(image, RenderedImage):
            return image

        return get_buffered_image(image)

    @staticmethod
    def get_buffered_image(image):
        if isinstance(image, BufferedImage):
            return image

        ImageUtils.wait_for_image("<unknown name>", image)
        width = image.get_width()
        height = image.get_height()

        buffered_image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        g = buffered_image.create_graphics()
        x = 0
        y = 0

        if width < 0 or height < 0:
            return None

        g.draw_image(image, 0, 0, None)

        ImageUtils.wait_for_image(None, new_image)

        return new_image

    @staticmethod
    def write_file(i, image_file):
        try:
            ImageIO.write(to_rendered_image(i), "png", image_file)
        except Exception as e:
            print(f"Error writing file: {e}")

    @staticmethod
    def read_file(image_file):
        return Image.open(image_file)

    @staticmethod
    def write_icon_to_png(icon, filename):
        try:
            buffi = BufferedImage(icon.get_width(), icon.get_height(), BufferedImage.TYPE_INT_ARGB)
            g = buffi.create_graphics()
            icon.paint(g, 0, 0)
            g.dispose()

            ImageIO.write(buffi, "png", File(filename))
        except Exception as e:
            print(f"Error writing file: {e}")

    @staticmethod
    def make_transparent(icon):
        return make_transparent(icon, DEFAULT_TRANSPARENCY_ALPHA)

    @staticmethod
    def make_transparent(icon, alpha):
        new_image = BufferedImage(icon.get_width(), icon.get_height(), BufferedImage.TYPE_INT_ARGB)
        g = new_image.create_graphics()
        x = 0

        if i.get_height() < right.get_height():
            y = (right.get_height() - left.get_height()) // 2
        else:
            y = 0

        g.draw_image(i, left, top, None)

        return ImageIcon(new_image)

    @staticmethod
    def create_scaled_image(image, width, height):
        scaled_image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        g = scaled_image.create_graphics()
        x = 0
        y = 0

        if i.get_height() < right.get_height():
            y = (right.get_height() - left.get_height()) // 2
        else:
            y = 0

        g.draw_image(i, left, top, None)

        return scaled_image

    @staticmethod
    def change_color(image, old_color, new_color):
        if isinstance(image, BufferedImage):
            buffered_image = image
        else:
            buffered_image = get_buffered_image(image)

        width = buffered_image.get_width()
        height = buffered_image.get_height()

        destination = [0] * 4

        for y in range(height):
            for x in range(width):
                pixel = buffered_image.get_pixel(x, y)
                r = (pixel[0] & 0xff) / 255.0
                g = (pixel[1] & 0xff) / 255.0
                b = (pixel[2] & 0ff) / 255.0

                if old_color.get_red() == pixel[0] and old_color.get_green() == pixel[1] and old_color.get_blue() == pixel[2]:
                    r = new_color.get_red()
                    g = new_color.get_green()
                    b = new_color.get_blue()

                gray = (r + g + b) / 3.0

                destination[0] = int(gray * 255)
                destination[1] = int(gray * 255)
                destination[2] = int(gray * 255)

        return Image.fromarray(destination, "RGBA")

    @staticmethod
    def get_media_tracker_component():
        if media_tracker_component is None:
            media_tracker_component = JComponent()

        return media_tracker_component

    @staticmethod
    def wait_for_image(image_name, image):
        if isinstance(image, BufferedImage):
            return True

        tracker = MediaTracker(get_media_tracker_component())
        max_waits = 20
        wait_time = 100
        tracker.add_image(image, 0)
        for i in range(max_waits):
            try:
                tracker.wait_for_id(0, wait_time)
                width = image.get_width()
                height = image.get_height()

                if width < 0 or height < 0:
                    continue

                return True
            except Exception as e:
                pass

        print(f"Timed out waiting for image to load after {max_waits * wait_time / 100} seconds; {image_name}")

        tracker.remove_image(image, 0)

        return False
