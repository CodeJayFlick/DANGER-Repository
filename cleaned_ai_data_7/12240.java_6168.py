class BitmapResource:
    BOTTOM_UP = 1
    # TODO: Add TOP_DOWN constant here
    
    def __init__(self, buf):
        self.initialize(buf)

    def initialize(self, buf):
        try:
            self.size = buf.get_int(0)
            self.width = buf.get_int(4)
            self.height = buf.get_int(8)
            self.planes = buf.get_short(12)
            self.bit_count = buf.get_short(14)
            self.compression = buf.get_int(16)
            self.size_image = buf.get_int(20)
            self.x_pels_per_meter = buf.get_int(24)
            self.y_pels_per_meter = buf.get_int(28)
            self.clr_used = buf.get_int(32)
            self.clr_important = buf.get_int(36)
            self.image_data_offset = self.size + self.get_color_map_length()
        except MemoryAccessException as e:
            raise IOException("Truncated header for bitmap at " + str(buf)) from e

    def get_mask_length(self):
        return 0

    @property
    def size(self):
        return self._size

    @property
    def width(self):
        return self._width

    @property
    def height(self):
        return self._height

    @property
    def planes(self):
        return self._planes

    @property
    def bit_count(self):
        return self._bit_count

    @property
    def compression(self):
        return self._compression

    @property
    def size_image(self):
        return self._size_image

    @property
    def raw_size_image(self):
        return self._raw_size_image

    @property
    def image_data_offset(self):
        return self._image_data_offset

    @property
    def row_order(self):
        return self._row_order

    BI_RGB = 0
    BI_RLE8 = 1
    BI_RLE4 = 2
    #BI_BITFIELDS = 3
    #BI_JPEG = 4
    #BI_PNG = 5
    #BI_CMYK = 6
    #BI_CMYKRLE8 = 7
    #BI_CMYKRLE4 = 8

    def get_color_map_length(self):
        if self.bit_count == 32 or self.bit_count == 24:
            return 0
        else:
            return self.get_clr_used() * 4

    @property
    def clr_used(self):
        if self._clr_used == 0:
            self._clr_used = (1 << self._bit_count)
        return self._clr_used

    def get_data_image(self, buf):
        if self.bit_count == 1:
            return self.get_one_plane_image(buf)
        elif self.bit_count == 4:
            return self.get_four_plane_image(buf)
        elif self.bit_count == 8:
            return self.get_eight_plane_image(buf)
        elif self.bit_count == 24 or self.bit_count == 32:
            return self.get_thirty_two_plane_image(buf)

    def get_one_plane_image(self, buf):
        # create the color model
        image = BufferedImage(0, 0, BufferedImage.TYPE_BYTE_INDEXED)
        dbuf = bytearray(image.getRaster().getDataBuffer()).tobytes()
        self.get_pixel_data(buf, dbuf)
        return BitmapDataImage(image)

    def get_four_plane_image(self, buf):
        colormap_data = self.get_rgb_data(buf)
        image_model = IndexColorModel(4, self._clr_used, colormap_data, 0, False, -1, bytearray())
        image = BufferedImage(self.width, self.height, BufferedImage.TYPE_BYTE_BINARY, image_model)
        dbuf = bytearray(image.getRaster().getDataBuffer()).tobytes()
        self.get_pixel_data(buf, dbuf)
        return BitmapDataImage(image)

    def get_eight_plane_image(self, buf):
        colormap_data = self.get_rgb_data(buf)
        image_model = IndexColorModel(8, self._clr_used, colormap_data, 0, False, -1, bytearray())
        image = BufferedImage(self.width, self.height, BufferedImage.TYPE_BYTE_BINARY, image_model)
        dbuf = bytearray(image.getRaster().getDataBuffer()).tobytes()
        self.get_pixel_data(buf, dbuf)
        return BitmapDataImage(image)

    def get_thirty_two_plane_image(self, buf):
        colormap_data = self.get_rgb_data(buf)
        image_model = IndexColorModel(32, self._clr_used, colormap_data, 0, False, -1, bytearray())
        image = BufferedImage(self.width, self.height, BufferedImage.TYPE_BYTE_BINARY, image_model)
        dbuf = bytearray(image.getRaster().getDataBuffer()).tobytes()
        self.get_pixel_data(buf, dbuf)
        return BitmapDataImage(image)

    def get_rgb_data(self, buf):
        cmap = [0] * (self._clr_used + 1)
        for i in range(len(cmap)):
            cmap[i] = ((buf.get_byte(i*4+2) & 0xff) << 16 | 
                       (buf.get_byte(i*4+1) & 0xff) << 8 |
                       buf.get_byte(i*4))
        return cmap

    def get_pixel_data(self, buf):
        h = self.height
        w = self.width
        max_buffer_offset = self.image_data_offset + len(buf)
        if self.compression == BI_RGB:
            raw_data_size = self.size_image
            decompressed_data_size = raw_data_size
            if hasattr(self, 'decompressed_data'):
                decompressed_data = bytearray(decompressed_data_size).tobytes()
                buf.get_bytes(decompressed_data, self.image_data_offset)
        elif self.compression == BI_RLE4:
            x = 0
            y = 0
            byte_width = w
            decompressed_data_size = byte_width * h
            if hasattr(self, 'decompressed_data'):
                decompressed_data = bytearray(decompressed_data_size).tobytes()
            read_offset = self.image_data_offset
            try:
                while True:
                    if read_offset >= max_buffer_offset:
                        raise MemoryAccessException("Bitmap resource decompression exceeded memory constraint at " + str(buf))
                    val = buf.get_byte(read_offset++)
                    if val == 0:  # escape
                        val = buf.get_byte(read_offset++)
                        if val == 1:
                            break  # End of Bitmap - break from loop
                        switch (val):
                            case 0:  # EOL
                                x = 0
                                y += 1
                                break
                            case 1:  # End of Bitmap
                                raise AssertionError()  # already handled
                            default:  # Absolute
                                num_follow = val & 0xff
                                if hasattr(self, 'decompressed_data'):
                                    bytes = bytearray(num_follow).tobytes()
                                    buf.get_bytes(bytes, read_offset)
                                    System.arraycopy(bytes, 0, decompressed_data, y * byte_width + x,
                                                     len(bytes))
                                    x += num_follow
                                read_offset += num_follow
            except MemoryAccessException as e:
                raise IOException("Unexpected Exception: " + str(e)) from e

class BitmapDataImage:
    def __init__(self, image):
        self.image = image

    @property
    def get_image_icon(self):
        return ResourceManager.get_image_icon_from_image("Bitmap Data Image", self.image)

    @property
    def get_image_file_type(self):
        return "bmp"
