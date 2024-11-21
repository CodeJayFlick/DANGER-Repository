Here is the translation of the Java code into Python:

```Python
import os
from PIL import Image
from io import BytesIO
from datetime import datetime

class FileUtil:
    @staticmethod
    def create_new_file(path):
        last_sep = path.rfind(os.sep)
        if last_sep > 0:
            dir_path = path[:last_sep]
            make_dir(dir_path)

        file = open(path, 'w')
        try:
            file.write('')
        except Exception as e:
            print(e)
        finally:
            file.close()

    @staticmethod
    def read_file(path):
        create_new_file(path)

        with open(path, 'r') as f:
            return f.read()

    @staticmethod
    def write_file(path, str):
        create_new_file(path)

        try:
            with open(path, 'w') as f:
                f.write(str)
        except Exception as e:
            print(e)

    @staticmethod
    def copy_file(source_path, dest_path):
        if not os.path.exists(source_path):
            return

        create_new_file(dest_path)

        with open(source_path, 'rb') as source_f:
            with open(dest_path, 'wb') as dest_f:
                while True:
                    chunk = source_f.read(1024)
                    if not chunk:
                        break
                    dest_f.write(chunk)

    @staticmethod
    def move_file(source_path, dest_path):
        copy_file(source_path, dest_path)
        os.remove(source_path)

    @staticmethod
    def delete_file(path):
        try:
            os.remove(path)
        except Exception as e:
            print(e)

    @staticmethod
    def is_exist_file(path):
        return os.path.exists(path)

    @staticmethod
    def make_dir(path):
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)

    @staticmethod
    def list_dir(path, lst):
        for f in os.listdir(path):
            full_path = os.path.join(path, f)
            if os.path.isdir(full_path):
                FileUtil.list_dir(full_path, lst)
            else:
                lst.append(f)

    @staticmethod
    def is_directory(path):
        return os.path.isdir(path)

    @staticmethod
    def is_file(path):
        return os.path.isfile(path)

    @staticmethod
    def get_file_length(path):
        if not os.path.exists(path):
            return 0

        return os.path.getsize(path)

    @staticmethod
    def convert_uri_to_file_path(context, uri):
        path = None
        if 'content' in uri.scheme:
            cursor = None
            try:
                cursor = context.contentResolver.query(uri)
                if cursor is not None and cursor.moveToFirst():
                    column_index = cursor.getColumnIndexOrThrow('_data')
                    return cursor.getString(column_index).replace('file://', '')
            except Exception as e:
                print(e)
            finally:
                if cursor is not None:
                    try:
                        cursor.close()
                    except Exception as e:
                        print(e)

        return path

    @staticmethod
    def save_bitmap(bitmap, dest_path):
        with open(dest_path, 'wb') as f:
            bitmap.save(f, format='PNG')

    @staticmethod
    def get_scaled_bitmap(path, max):
        img = Image.open(path)
        width, height = img.size
        rate = 0.0

        if width > height:
            rate = max / float(width)
            height = int(height * rate)
            width = max
        else:
            rate = max / float(height)
            width = int(width * rate)
            height = max

        return img.resize((width, height), Image.ANTIALIAS)

    @staticmethod
    def calculate_in_sample_size(options, req_width, req_height):
        out_width, out_height = options.outWidth, options.outHeight
        in_sample_size = 1

        if out_height > req_height or out_width > req_width:
            half_height = out_height // 2
            half_width = out_width // 2

            while (half_height / in_sample_size) >= req_height and (half_width / in_sample_size) >= req_width:
                in_sample_size *= 2

        return in_sample_size

    @staticmethod
    def decode_sample_bitmap_from_path(path, req_width, req_height):
        options = Image.open(path).convert('RGB').getpixel((0, 0))
        options.injustdecodebounds = True
        img = Image.open(path)
        options.insamplesize = FileUtil.calculate_in_sample_size(options, req_width, req_height)

        return img.resize((req_width, req_height), Image.ANTIALIAS).convert('RGB')

    @staticmethod
    def resize_bitmap_file_retain_ratio(from_path, dest_path, max):
        if not os.path.exists(from_path):
            return

        bitmap = FileUtil.get_scaled_bitmap(from_path, max)
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def resize_bitmap_file_to_square(from_path, dest_path, max):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        bitmap = img.resize((max, max), Image.ANTIALIAS)
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def resize_bitmap_file_to_circle(from_path, dest_path):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        bitmap = img.resize((img.size[0], img.size[1]), Image.ANTIALIAS)
        draw = ImageDraw.Draw(bitmap)

        color = (255, 51, 153)  # RGB values for red
        paint = ImageDraw.ImageDraw()
        rect = (0, 0, bitmap.size[0], bitmap.size[1])
        draw.ellipse(rect, fill=color)

        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def resize_bitmap_file_with_rounded_border(from_path, dest_path, pixels):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        bitmap = img.resize((img.size[0], img.size[1]), Image.ANTIALIAS)
        draw = ImageDraw.Draw(bitmap)

        color = (255, 51, 153)  # RGB values for red
        paint = ImageDraw.ImageDraw()
        rectf = RectF(0, 0, bitmap.size[0], bitmap.size[1])
        draw.rounded_rectangle(rectf, pixels, fill=color)

        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def crop_bitmap_file_from_center(from_path, dest_path, w, h):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        width, height = img.size
        x, y = 0, 0

        if width < w and height < h:
            return

        if width > w:
            x = (width - w) // 2
        if height > h:
            y = (height - h) // 2

        cw, ch = w, h

        if w > width:
            cw = width
        if h > height:
            ch = height

        bitmap = img.crop((x, y, x + cw, y + ch))
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def rotate_bitmap_file(from_path, dest_path, angle):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        bitmap = img.rotate(angle)
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def set_bitmap_file_color_filter(from_path, dest_path, color):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        draw = ImageDraw.Draw(img)
        paint = ImageDraw.ImageDraw()
        filter = ImageEnhance.Color(img)

        canvas = BytesIO()
        img.save(canvas, 'PNG')

        bitmap = Image.open(BytesIO(filter.enhance(0.5).getdata()))
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def set_bitmap_file_brightness(from_path, dest_path, brightness):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        draw = ImageDraw.Draw(img)
        paint = ImageDraw.ImageDraw()
        filter = ImageEnhance.Brightness(img)

        canvas = BytesIO()
        img.save(canvas, 'PNG')

        bitmap = Image.open(BytesIO(filter.enhance(brightness).getdata()))
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def set_bitmap_file_contrast(from_path, dest_path, contrast):
        if not os.path.exists(from_path):
            return

        img = Image.open(from_path).convert('RGB')
        draw = ImageDraw.Draw(img)
        paint = ImageDraw.ImageDraw()
        filter = ImageEnhance.Contrast(img)

        canvas = BytesIO()
        img.save(canvas, 'PNG')

        bitmap = Image.open(BytesIO(filter.enhance(contrast).getdata()))
        FileUtil.save_bitmap(bitmap, dest_path)

    @staticmethod
    def get_jpeg_rotate(file_path):
        rotate = 0

        try:
            exif = ExifTags()
            i_orientation = exif.get_attribute_int(exif.TAG_ORIENTATION, -1)
            if i_orientation == 2:  # Rotate 90
                return 90
            elif i_orientation == 3:  # Rotate 180
                return 180
            elif i_orientation == 4:  # Rotate 270
                return 270

        except Exception as e:
            print(e)

        return rotate

    @staticmethod
    def create_new_picture_file(context):
        date = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"{date}.jpg"
        path = os.path.join(context.get_external_files_dir(), "DCIM", file_name)
        return File(path)

```

Note: The `ImageDraw` and `ExifTags` classes are not part of the Python standard library. You may need to install additional libraries or modules, such as Pillow (PIL) for image processing and ExifRead for reading EXIF tags.

Also note that some Java code has been modified or removed in this translation due to differences between languages.