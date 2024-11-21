import os

class LinuxPtyEndpoint:
    def __init__(self, fd):
        self.output_stream = open(fd, 'wb')
        self.input_stream = open(fd, 'rb')

    def get_output_stream(self):
        return self.output_stream

    def get_input_stream(self):
        return self.input_stream
