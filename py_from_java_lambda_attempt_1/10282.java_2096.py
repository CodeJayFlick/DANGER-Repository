Here is the equivalent Python code:

```Python
import os
from io import BytesIO
from zipfile import ZipFile


class ZipArchiveBuilder:
    def __init__(self, output_file):
        with open(output_file, 'wb') as f:
            self.archive = ZipFile(f, 'w')
```

Note that this is a simplified translation and does not include the full functionality of the original Java code. The `ZipArchiveBuilder` class in Python only initializes an instance variable for the archive file, whereas the original Java code also includes methods to add files to the archive.

Here's how you could extend this basic implementation:

```Python
class ZipArchiveBuilder:
    def __init__(self, output_file):
        with open(output_file, 'wb') as f:
            self.archive = ZipFile(f, 'w')

    def add_file(self, file_path):
        zip_info = zipfile.ZipInfo(os.path.basename(file_path))
        with open(file_path, 'rb') as f_in:
            self.archive.writestr(zip_info, f_in.read())

# Usage
builder = ZipArchiveBuilder('output.zip')
builder.add_file('path/to/file1.txt')
builder.add_file('path/to/file2.txt')
```

This code creates a `ZipArchiveBuilder` class that can be used to add files to an archive. The `add_file` method takes the path of a file and adds it to the archive.