import tkinter as tk
from datetime import date
from PIL import ImageTk, Image

class EventDisplayComponentProvider:
    def __init__(self):
        self.text_area = tk.Text()
        self.scroll-pane = tk.Scrollbar(master=tk.Tk())
        self.viewport = self.scroll-pane.set()

        self.bottom = (0, 10000)

        self.clear_action = None
        self.create_action()

    def get_component(self):
        return self.scroll-pane

    def process_event(self, event):
        current_date = date.today().strftime("%Y-%m-%d %H:%M:%S")
        
        self.text_area.insert('end', f"{current_date}      {event}\n")

        if isinstance(event, ProgramLocationPluginEvent):
            location = event.get_location()
            self.text_area.insert('end', f"\t{location}\n")

    def print_location_details(self, event):
        pass

    def create_action(self):
        self.clear_action = tk.Button(master=tk.Tk(), text="Clear Display", command=self.clear)
        
        icon_path = "images/erase16.png"
        image = Image.open(icon_path).resize((16, 16))
        photo = ImageTk.PhotoImage(image)

        self.clear_action.config(image=photo)
        self.clear_action.image = photo

    def clear(self):
        self.text_area.delete('1.0', 'end')

# Usage
provider = EventDisplayComponentProvider()
