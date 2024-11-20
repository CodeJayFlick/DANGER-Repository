import os
from datetime import datetime
from shutil import copyfile, move
from collections import defaultdict

class FileUtils:
    def __init__(self):
        pass

    @staticmethod
    def get_backup_suffix():
        return str(datetime.now())

    @staticmethod
    def backup(f):
        name = f.name
        c = name.rfind('.')
        ext = '' if c == -1 else name[c + 1:]
        if c != -1:
            name = name[:c]
        backup_folder = os.path.join(os.path.dirname(f), 'backups')
        if not os.path.exists(backup_folder):
            try:
                os.makedirs(backup_folder)
            except Exception as e:
                raise IOException("Cannot create backups folder") from e
        backup_file_name = f"{name}_{FileUtils.get_backup_suffix()}{'' if ext == '' else '.' + ext}"
        backup_file_path = os.path.join(backup_folder, backup_file_name)
        try:
            copyfile(f, backup_file_path)
        except Exception as e:
            raise IOException("Backup file already exists") from e
        return backup_file_path

    @staticmethod
    def move(from_file, to_file):
        if not os.path.exists(to_file.parent):
            os.makedirs(to_file.parent)
        try:
            move(from_file, to_file)
        except Exception as e:
            raise IOException("Can't rename file") from e

    @staticmethod
    def copy(from_file, to_file):
        with open(from_file, 'rb') as f_in:
            with open(to_file, 'wb') as f_out:
                while True:
                    chunk = f_in.read(4096)
                    if not chunk:
                        break
                    f_out.write(chunk)

    @staticmethod
    def rename_all(directory, renamer):
        changed_files = []
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isdir(file_path):
                changed_files.extend(FileUtils.rename_all(file_path, renamer))
            else:
                name = file
                new_name = renamer(name) if renamer is not None and callable(renamer) else name
                if new_name != name:
                    to_file = os.path.join(os.path.dirname(file_path), new_name)
                    try:
                        FileUtils.move(file_path, to_file)
                    except Exception as e:
                        raise IOException("Renaming file caused an exception") from e
                    changed_files.append(to_file)
        return changed_files

    @staticmethod
    def save(in_stream, file):
        with open(file, 'wb') as f_out:
            while True:
                chunk = in_stream.read(16 * 1024)
                if not chunk:
                    break
                f_out.write(chunk)

class IOException(Exception):
    pass
