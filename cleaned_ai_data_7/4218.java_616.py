import os
from tkinter import filedialog
from PIL import Image

class ResourceActionsPlugin:
    GRAPHIC_FORMATS_FILTER = ["png", "gif", "bmp", "jpg"]

    def __init__(self, tool):
        self.tool = tool

    def init(self):
        super().init()

        save_image_as_new_format_action = {
            'name': 'Save Image New Format',
            'context': ProgramLocationActionContext,
            'valid_context_when': lambda plac: isinstance(plac.get_location(), ResourceFieldLocation) and (plac.get_location()).is_data_image_resource(),
            'on_action': self.save_image_as_new_format
        }
        save_image_original_bytes_action = {
            'name': 'Save Image Original Bytes',
            'context': ProgramLocationActionContext,
            'valid_context_when': lambda plac: isinstance(plac.get_location(), ResourceFieldLocation) and (plac.get_location()).is_data_image_resource(),
            'on_action': self.save_image_original_bytes
        }

        tool.set_menu_group(['Data', 'Save Image'], 'A_save_image')

    def save_image_as_new_format(self, image_location):
        data = image_location.get_resource_data()
        if not (data and isinstance(data.value, DataImage)):
            return

        data_image = data.value
        chooser = filedialog.asksaveasfilename(parent=self.tool.get_active_window(), title='Save Image File As', initialdir=os.getcwd())
        if chooser:
            extension = os.path.splitext(chooser)[1]
            if not extension:
                Msg.show_error(self, None, 'Missing File Type', 'Filename must specify a supported graphics format extension.')
                return

            try:
                icon = data_image.get_image_icon()
                buffy = Image.open(icon.get_image()).convert('RGB')
                success = buffy.save(chooser)
                if not success:
                    Msg.show_error(self, None, 'Image File Error', f'Failed to save {chooser}. Either unsupported image format or incompatible image features with selected image format.')
                    return
                self.tool.set_status_info(f'Image resource at {data.get_address()} saved as: {chooser}')
            except Exception as e:
                Msg.show_error(self, None, 'Error Saving Image File', f'Failed to save image. Error: {str(e)}')

    def save_image_original_bytes(self, image_location):
        data = image_location.get_resource_data()
        if not (data and isinstance(data.value, DataImage)):
            return

        try:
            chooser = filedialog.asksaveasfilename(parent=self.tool.get_active_window(), title='Save Image File As', initialdir=os.getcwd())
            if chooser:
                bytes = data.get_bytes()
                with open(chooser, 'wb') as f:
                    f.write(bytes)
                self.tool.set_status_info(f'Image resource at {data.get_address()} saved as: {chooser}')
        except Exception as e:
            Msg.show_error(self, None, 'Error Saving Image File', f'Failed to save image. Error: {str(e)}')
