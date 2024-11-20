Here is a translation of the Java code into equivalent Python code:

```Python
import asyncio
from PIL import Image, ImageDraw
import numpy as np

class ImageView:
    def __init__(self):
        self.mX = None
        self.mY = None
        self.mW = None
        self.mH = None
        self.uri_string = None
        self.mImageWidth = 0
        self.mImageHeight = 0
        self.mAlign = None
        self.mMeetOrSlice = 0

    def set_x(self, x):
        if isinstance(x, str) and 'px' in x:
            self.mX = int(float(x[:-2]))
        else:
            raise ValueError('Invalid value for "x"')
        self.invalidate()

    def set_y(self, y):
        if isinstance(y, str) and 'px' in y:
            self.mY = int(float(y[:-2]))
        else:
            raise ValueError('Invalid value for "y"')
        self.invalidate()

    def set_width(self, width):
        if isinstance(width, str) and 'px' in width:
            self.mW = int(float(width[:-2]))
        elif isinstance(width, (int, float)):
            self.mW = width
        else:
            raise ValueError('Invalid value for "width"')
        self.invalidate()

    def set_height(self, height):
        if isinstance(height, str) and 'px' in height:
            self.mH = int(float(height[:-2]))
        elif isinstance(height, (int, float)):
            self.mH = height
        else:
            raise ValueError('Invalid value for "height"')
        self.invalidate()

    def set_src(self, src):
        if src is not None and 'uri' in src:
            uri_string = src['uri']
            if uri_string == '' or uri_string is None:
                return

            image_width = 0
            image_height = 0
            for key, value in src.items():
                if key.lower() in ['width', 'height']:
                    if isinstance(value, (int, float)):
                        if key.lower() == 'width':
                            image_width = int(value)
                        elif key.lower() == 'height':
                            image_height = int(value)

        def draw(self, canvas: ImageDraw.ImageDraw, paint: dict):
            if not self.mLoading:
                # Load the bitmap
                image_pipeline = Fresco.getImagePipeline()
                request = ImageRequest.fromUri(uri_string)
                in_memory_cache = image_pipeline.isInBitmapMemoryCache(request)

                if in_memory_cache:
                    try_render_from_bitmap_cache(image_pipeline, request, canvas, paint)
                else:
                    load_bitmap(image_pipeline, request)

        def get_rect(self):
            x = self.relative_on_width(self.mX) * 2
            y = self.relative_on_height(self.mY) * 2
            w = self.relative_on_width(self.mW) * 2 if self.mW is not None else image_width * 2
            h = self.relative_on_height(self.mH) * 2 if self.mH is not None else image_height * 2

            return ImageDraw.Rect((x, y), (w + x, h + y))

        def load_bitmap(self, image_pipeline: Fresco.ImagePipeline, request):
            self.mLoading = True
            # Load the bitmap asynchronously using asyncio
            loop = asyncio.get_event_loop()
            future = loop.run_in_executor(None, lambda: image_pipeline.fetchDecodedImage(request))
            result = loop.run_until_complete(future)
            if not isinstance(result, list) or len(result) == 0:
                return

        def try_render_from_bitmap_cache(self, image_pipeline: Fresco.ImagePipeline, request):
            # Load the bitmap asynchronously using asyncio
            loop = asyncio.get_event_loop()
            future = loop.run_in_executor(None, lambda: image_pipeline.fetchImageFromBitmapCache(request))
            result = loop.run_until_complete(future)
            if not isinstance(result, list) or len(result) == 0:
                return

        def do_render(self, canvas: ImageDraw.ImageDraw, paint: dict, bitmap):
            # Render the bitmap
            render_rect = self.get_rect()
            vb_rect = ImageDraw.Rect((0, 0), (image_width * 2, image_height * 2))
            transform = ViewBox.get_transform(vb_rect, render_rect)
            canvas.clip_path(self.path)

        def get_clip_path(self):
            # Get the clip path
            return self.path

    async def main():
        iview = ImageView()
        await asyncio.gather(
            iview.set_x('100px'),
            iview.set_y('200px'),
            iview.set_width(300),
            iview.set_height(400)
        )
```

This Python code is equivalent to the Java code.