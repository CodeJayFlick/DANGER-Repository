import os
from io import BufferedReader, BufferedWriter, BufferedInputStream, BufferedOutputStream


class FSFactory:
    def get_file_with_parent(self, pathname):
        return os.path.dirname(pathname)

    def get_file(self, pathname):
        return os.path.basename(pathname)

    def get_file(self, parent, child):
        if not isinstance(parent, str):
            raise TypeError("Parent must be a string")
        return os.path.join(parent, child)

    def get_file(self, parent, child):
        if not isinstance(parent, str) or not isinstance(child, str):
            raise TypeError("Both parent and child must be strings")
        return os.path.join(parent, child)

    def get_file(self, uri):
        # This method is not directly translatable to Python
        pass

    def get_buffered_reader(self, file_path):
        with open(file_path) as f:
            reader = BufferedReader(f)
        return reader

    def get_buffered_writer(self, file_path, append=False):
        if append and os.path.exists(file_path):
            mode = 'a'
        else:
            mode = 'w'

        writer = BufferedWriter(open(file_path, mode))
        return writer

    def get_buffered_input_stream(self, file_path):
        with open(file_path) as f:
            stream = BufferedInputStream(f)
        return stream

    def get_buffered_output_stream(self, file_path):
        with open(file_path, 'w') as f:
            stream = BufferedOutputStream(f)
        return stream

    def move_file(self, src_file, dest_file):
        os.rename(src_file, dest_file)

    def list_files_by_suffix(self, file_folder, suffix):
        files = [os.path.join(file_folder, f) for f in os.listdir(file_folder) if f.endswith(suffix)]
        return files

    def list_files_by_prefix(self, file_folder, prefix):
        files = [os.path.join(file_folder, f) for f in os.listdir(file_folder) if f.startswith(prefix)]
        return files

    def delete_if_exists(self, file_path):
        try:
            os.remove(file_path)
            return True
        except FileNotFoundError:
            return False
