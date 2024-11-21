import tkinter as tk
from PIL import ImageGrab

class DisassembledViewPluginScreenShots:
    def __init__(self):
        pass

    def test_disassembled_view_plugin_main(self):
        # set_tool_size(900, 600)
        self.set_window_size()

        # position_listing_top(0x4017ad)
        self.position_instruction(0x4017ad)

        # close_provider(DataTypesProvider.class); close_provider(ViewManagerComponentProvider.class);
        self.close_providers()

        # perform_action("Disassembled View", "DockingWindows", true);
        self.perform_action("Disassembled View", "DockingWindows")

        # capture_window();
        self.capture_screen()

    def set_window_size(self):
        pass

    def position_instruction(self, address):
        pass

    def close_providers(self):
        pass

    def perform_action(self, action_name1, action_name2):
        pass

    def capture_screen(self):
        img = ImageGrab.grab()
        img.save("screenshot.png")

    # Highlight the component
    # Adjust the highlight.
    def draw_rectangle(self, color, rectangle, thickness):
        root = tk.Tk()
        canvas = tk.Canvas(root, width=rectangle.width, height=rectangle.height)
        canvas.pack()
        canvas.create_rectangle(0, 0, rectangle.width - (2 * thickness), rectangle.height - (2 * thickness), fill=color)
        root.mainloop()

# Usage
plugin = DisassembledViewPluginScreenShots()
plugin.test_disassembled_view_plugin_main()
