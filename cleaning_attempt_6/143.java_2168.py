import tkinter as tk
from tkinter import filedialog
import xml.etree.ElementTree as ET
import os

class ExportAsXMLAction:
    def __init__(self):
        self.file_ext = ".xml"
        self.file_mode = "files_only"

    def set_popup_menu(self, path):
        return {"Export as...", "XML"}

    def set_key_binding_data(self):
        return {"key": tk.K_e, "shift_down_mask": True}

    def set_help_location(self):
        return {"owner": "export_as_xml", "help_location": ""}

    def do_action(self, container, file_path):
        self.write_xml(container, file_path)

    def write_xml(self, container, file_path):
        if not container:
            return
        root = ET.tostring(container)
        joined_path = os.path.join(container.get_target_object().get_path(), ".")
        ET.SubElement(root, "Path").text = joined_path

        try:
            with open(file_path, 'w') as f:
                f.write(ET.fromstring(root).decode('utf-8'))
        except Exception as e:
            print(e)
