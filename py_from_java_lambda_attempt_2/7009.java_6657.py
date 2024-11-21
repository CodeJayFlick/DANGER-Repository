Here is the translation of the Java code into equivalent Python:

```Python
import os
import shutil
from xml.etree import ElementTree as ET
from zipfile import ZipFile
try:
    from androidpath import AndroidPath
except ImportError:
    pass

class ResourceFile:
    def __init__(self, directory, name):
        self.directory = directory
        self.name = name

class MessageLog:
    def __init__(self):
        self.messages = []

    def appendMsg(self, message):
        self.messages.append(message)

    def copyFrom(self, log):
        for msg in log.messages:
            self.appendMsg(msg)


class AndroidProjectCreator:
    android_directory = None
    apk_file_fsrl = None
    eclipse_project_directory = None
    src_directory = None
    gen_directory = None
    asset_directory = None

    def __init__(self, apk_file_fsrl, eclipse_project_directory):
        self.apk_file_fsrl = apk_file_fsrl
        self.eclipse_project_directory = eclipse_project_directory

    def create(self, monitor=None):
        if not os.path.exists(self.eclipse_project_directory):
            os.makedirs(self.eclipse_project_directory)

        src_dir_path = os.path.join(self.eclipse_project_directory, 'src')
        gen_dir_path = os.path.join(self.eclipse_project_directory, 'gen')
        asset_dir_path = os.path.join(self.eclipse_project_directory, 'asset')

        if not os.path.exists(src_dir_path):
            os.makedirs(src_dir_path)

        if not os.path.exists(gen_dir_path):
            os.makedirs(gen_dir_path)

        if not os.path.exists(asset_dir_path):
            os.makedirs(asset_dir_path)

        try:
            with ZipFile(apk_file_fsrl, 'r') as zip_ref:
                listing = [file for file in zip_ref.infolist()]
                self.process_listing(self.eclipse_project_directory, zip_ref, listing, monitor)
        except Exception as e:
            print(f"Error: {e}")

    def process_listing(self, output_directory, fs, listing, monitor=None):
        for child in listing:
            if not os.path.exists(os.path.join(output_directory, child.filename)):
                with open(os.path.join(output_directory, child.filename), 'wb') as f:
                    f.write(fs.read(child))

    def fixup_project_file(self, project_file_path):
        try:
            tree = ET.parse(project_file_path)
            root = tree.getroot()
            name_element = root.find('.//name')
            if name_element is not None:
                name_element.text = self.apk_file_fsrl
                tree.write(project_file_path)
        except Exception as e:
            print(f"Error: {e}")

    def copy_file(self, input_file_path, output_directory, output_name):
        try:
            with open(input_file_path, 'rb') as f_in:
                with open(os.path.join(output_directory, output_name), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        except Exception as e:
            print(f"Error: {e}")

    def process_dex(self, output_directory, dex_file_path):
        try:
            with ZipFile(dex_file_path, 'r') as zip_ref:
                jar_file = [f for f in zip_ref.infolist() if f.filename.endswith('.jar')]
                self.process_jar(output_directory, jar_file[0].filename)
        except Exception as e:
            print(f"Error: {e}")

    def process_jar(self, output_directory, jar_file_path):
        try:
            with ZipFile(jar_file_path, 'r') as zip_ref:
                listing = [file for file in zip_ref.infolist()]
                self.process_listing(output_directory, zip_ref, listing)
        except Exception as e:
            print(f"Error: {e}")

    def process_class(self, output_directory, class_file_path):
        try:
            with open(class_file_path, 'rb') as f_in:
                with open(os.path.join(output_directory, os.path.basename(class_file_path)), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        except Exception as e:
            print(f"Error: {e}")

    def process_xml(self, output_directory, container_file_path):
        try:
            with open(container_file_path, 'rb') as f_in:
                with open(os.path.join(output_directory, os.path.basename(container_file_path)), 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        except Exception as e:
            print(f"Error: {e}")

    def process_resources(self):
        pass

if __name__ == "__main__":
    android_project_creator = AndroidProjectCreator('path_to_apk_file', 'path_to_eclipse_project_directory')
    android_project_creator.create()
```

Please note that this is a translation of the Java code into Python, and it may not be exactly equivalent. The original Java code might have some specific functionality or edge cases that are not fully translated here.