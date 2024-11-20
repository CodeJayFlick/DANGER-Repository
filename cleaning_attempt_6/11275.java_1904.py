import os
import io
import zipfile

class ProjectJarWriter:
    PROPERTIES_FILE_NAME = ".properties"
    ORIGINAL_PROPERTIES_FILE_NAME = "original" + PROPERTIES_FILE_NAME

    def __init__(self, jar_out):
        self.jar_out = jar_out

    def output_file(self, base_file, jar_path):
        succeeded = True
        if os.path.isdir(base_file):
            return False

        try:
            with open(base_file, 'rb') as in_file:
                bytes_read = 0
                while (bytes := in_file.read(4096)) != b'':
                    self.jar_out.writestr(f"{jar_path}{os.path.basename(base_file)}", bytes)
                    bytes_read += len(bytes)
        except FileNotFoundError:
            print("Unexpected Exception:", "File not found")
            succeeded = False
        except IOError as e:
            print("Unexpected Exception:", str(e))
            succeeded = False

        return succeeded


# Example usage:
jar_out = zipfile.ZipFile('output.jar', 'w')
writer = ProjectJarWriter(jar_out)
base_file = '/path/to/file.txt'
jar_path = 'dir/'
print(writer.output_file(base_file, jar_path))  # True or False
