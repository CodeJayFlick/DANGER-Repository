import os
from io import BytesIO
from zipfile import ZipFile


class ZipArchiveBuilder:
    def __init__(self, output_file):
        with open(output_file, 'wb') as f:
            self.archive = ZipFile(f, 'w')
