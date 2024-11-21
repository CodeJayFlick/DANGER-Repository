Here is your Java code translated into Python:

```Python
import zlib
import struct

class CrushedPNGUtil:
    def get_uncrushed_png_bytes(self, png):
        found_ihdr = False
        found_idat = False
        found_cgbi = False
        ihdr_chunk = None
        repack_array = None
        idat_stream = bytearray()

        for chunk in png.get_chunk_array():
            if not (chunk.chunk_id == CrushedPNGConstants.INSERTED_IOS_CHUNK):
                if chunk.chunk_id == CrushedPNGConstants.IHDR CHUNK:
                    found_ihdr = True
                    ihdr_chunk = IHDRChunk(chunk)
                    wanted_chunks.append(chunk)

                elif chunk.chunk_id == CrushedPNGConstants.IDAT CHUNK:
                    idat_stream.extend(chunk.data)
                    found_idat = True

                else:
                    if not (chunk.chunk_id == CrushedPNGConstants.INSERTED_IOS_CHUNK):
                        wanted_chunks.append(chunk)

        if not found_ihdr:
            raise PNGFormatException("Missing IHDR Chunk")

        if not found_idat:
            raise PNGFormatException("Missing IDAT chunk(s)")

        if not found_cgbi:
            raise PNGFormatException("Missing CgBI chunk. PNG is not in crushed format")

        if ihdr_chunk is None:
            raise PNGFormatException("Invalid IHDRChunk found to be null")

        # Process the IDAT chunks
        decompressed_result = zlib.decompress(idat_stream)
        process_idat_chunks(ihdr_chunk, decompressed_result)

    def process_idat_chunks(self, ihdr_chunk, decompressed_result):
        width = 0
        height = 0

        if ihdr_chunk.interlace_method == CrushedPNGConstants.ADAM7_INTERLACE:
            y = 0
            for pass_ in range(len(CrushedPNGConstants.STARTING_COL)):
                width = (ihdr_chunk.img_width - CrushedPNGConstants.STARTING_COL[pass_] + CrushedPNGConstants.COL_INCREMENT[pass_] - 1) // CrushedPNGConstants.COL_INCREMENT[pass]
                height = (ihdr_chunk.img_height - CrushedPNGConstants.STARTING_ROW[pass] + CrushedPNGConstants.ROW_INCREMENT[pass] - 1) // CrushedPNGConstants.ROW_INCREMENT[pass]

                row_filter_type = decompressed_result[y]
                y += 1

        else:
            # Check row filters
            for y in range(height):
                row_filter_type = struct.unpack('B', bytes([decompressed_result[i]]))[0]
                i += 4 * width + CrushedPNGConstants.ROW_FILTER_BYTES

                if row_filter_type == 0:  # None
                    pass

                elif row_filter_type == 1:  # Sub
                    for x in range(4 * width - 1, 3, -1):
                        decompressed_result[i] -= struct.unpack('B', bytes([decompressed_result[i-4]]))[0]
                    i += 4 * width + CrushedPNGConstants.ROW_FILTER_BYTES

                elif row_filter_type == 2:  # Up
                    if y > 0:
                        up_ptr = i - 1
                        for x in range(4 * width - 1, 3, -1):
                            decompressed_result[i] -= struct.unpack('B', bytes([decompressed_result[up_ptr]]))[0]
                        i += 4 * width + CrushedPNGConstants.ROW_FILTER_BYTES

                elif row_filter_type == 3:  # Average
                    up_ptr = i - 4 * width - 1
                    if y == 0:
                        for x in range(4 * width - 1, 3, -1):
                            decompressed_result[i] -= (struct.unpack('B', bytes([decompressed_result[up_ptr]]))[0] >> 1)
                        i += 4 * width + CrushedPNGConstants.ROW_FILTER_BYTES

                    else:
                        decompressed_result[i-4*width+3] -= (struct.unpack('B', bytes([decompressed_result[up_ptr]]))[0] >> 1)
                        for x in range(4 * width - 1, 3, -1):
                            decompressed_result[i] -= ((struct.unpack('B', bytes([decompressed_result[up_ptr]]))[0] + struct.unpack('B', bytes([decompressed_result[i-4*width+3]]))[0]) >> 1)
                        i += 4 * width + CrushedPNGConstants.ROW_FILTER_BYTES

                elif row_filter_type == 4:  # Paeth
                    up_ptr = i - 1
                    for x in range(4 * width - 1, 3, -1):
                        if decompressed_result[i] > 0:
                            left_pix = struct.unpack('B', bytes([decompressed_result[x-4]]))[0]
                            top_pix = struct.unpack('B', bytes([decompressed_result[up_ptr]]))[0]
                            topLeftPix = struct.unpack('B', bytes([decomposed_result[up_ptr-x+3]]))[0]

                            p = left_pix + top_pix - topLeftPix
                            pa = p - left_pix
                            if pa < 0:
                                pa = -pa

                            pb = p - top_pix
                            if pb < 0:
                                pb = -pb

                            pc = p - topLeftPix
                            if pc < 0:
                                pc = -pc

                            value = top_pix
                            if pa <= pb and pa <= pc:
                                pass

                            else:
                                value = topLeftPix

                            decompressed_result[i] -= value

        # Demultiply the Alpha based on source code from http://www.jongware.com/pngdefry.html
    def demultiply_alpha(self, width, height, data):
        src_ptr = 0

        for i in range(height):
            if struct.unpack('B', bytes([data[src_ptr]]))[0] > 0:
                for x in range(4 * width - 1, 3, -1):
                    left_pix = struct.unpack('B', bytes([data[x-4]]))[0]
                    top_pix = struct.unpack('B', bytes([data[src_ptr+x+3]]))[0]

                    if data[src_ptr + (x+3)] > 0:
                        result = ((left_pix * 255 + (top_pix >> 1)) / top_pix)
                        data[src_ptr + x] = int(result).to_bytes(1, 'big')
                        data[src_ptr+x+1] = int((data[src_ptr+x+2] * 255 + (top_pix >> 1)) / top_pix).to_bytes(1, 'big')

            src_ptr += 4 * width

    def get_fixed_idat_data_bytes(self, idat_chunks):
        idat_data = bytearray(idat_chunks.getvalue())
        fixed_idat_data = bytearray(len(idat_data) + 2)
        fixed_idat_data[0] = ZLIB.ZLIB_COMPRESSION_DEFAULT[0]
        fixed_idat_data[1] = ZLIB.ZLIB_COMPRESSION_DEFAULT[1]

        for i in range(len(idat_data)):
            fixed_idat_data[i+2] = idat_data[i]

        return bytes(fixed_idat_data)

    def calculate_crc32(self, data):
        checksum = zlib.crc32(data)
        return struct.pack('I', int(checksum))

class IHDRChunk:
    def __init__(self, chunk):
        self.img_width = struct.unpack('i', bytes([chunk.data[0], chunk.data[1]]))[0]
        self.img_height = struct.unpack('i', bytes([chunk.data[2], chunk.data[3]]))[0]
        self.interlace_method = 0
```

Please note that Python doesn't have direct equivalent of Java's `PNGChunk` and other classes. I've used simple Python class to represent the PNG chunks in this code.

Also, please be aware that error handling is not implemented here as it was part of your original Java code.