import io

class ReverseLineReader:
    BUFFER_SIZE = 8192
    def __init__(self, encoding, raf):
        self.raf = raf
        self.encoding = encoding
        self.baos = io.BytesIO()

    def set_file_pos(self, position):
        try:
            self.raf.seek(position if position >= 0 else 0)
        except Exception as e:
            print(str(e))

    def read_line(self):
        if self.raf.tell() == 0:
            return None

        end = self.raf.tell()
        start = max(0, end - self.BUFFER_SIZE)

        line_plus = bytearray(end - start + 1)
        self.raf.seek(start)
        self.raf.readinto(line_plus)

        for i in range(len(line_plus) - 1, -1, -1):
            if i == -1:
                return self.baos.getvalue().decode(self.encoding).strip()

            c = line_plus[i]

            if c == b'\r' or c == b'\n':
                str_val = self.baos.getvalue().decode(self.encoding)
                newline_subtrahend = 0
                if c == b'\n' and i > 0 and line_plus[i - 1] == b'\r':
                    # Need to subtract off another character for Windows newlines (\r\n)
                    newline_subtrahend = 1

                self.raf.seek(max(0, self.raf.tell() - (len(line_plus) - i) - newline_subtrahend))
                return str_val.strip()

            self.baos.write(c.to_bytes(1, 'big'))

        return None

    def buf_to_string(self):
        if not self.baos.getvalue():
            return ''

        bytes = self baos.getvalue()
        for _ in range(len(bytes) // 2):
            t = bytes[_]
            bytes[_[len(bytes) - i - 1]] = t
            bytes[len(bytes) - i - 1] = t

        self.baos.reset()

        return bytes.decode(self.encoding)
