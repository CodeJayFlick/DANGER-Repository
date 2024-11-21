import tkinter as tk
from threading import Timer
from datetime import date

class StatusBar:
    STATUS_ BORDER = {'top': 1, 'left': 2, 'bottom': 1, 'right': 2}
    MESSAGE_QUEUE_MAX_SIZE = 10

    def __init__(self):
        self.root = tk.Tk()
        self.status_label = tk.Label(self.root)
        self.home_button_panel = tk.Frame(self.root)
        self.status_area_panel = tk.Frame(self.root)

        self.create_widgets()

    def create_widgets(self):
        self.status_label.pack(side=tk.LEFT, fill=tk.X)
        self.home_button_panel.pack(side=tk.LEFT, fill=tk.Y)
        self.status_area_panel.pack(side=tk.RIGHT, fill=tk.Y)

    def set_home_button(self, icon, callback):
        button = tk.Button(self.home_button_panel, image=icon, command=callback)
        button.pack()

    def add_status_item(self, component, border=True, right_side=False):
        panel = tk.Frame(self.status_area_panel)
        if border:
            panel.borderwidth = 1
            panel.relief=tk.GROOVE

        panel.add(component)

        self.status_area_panel.add(panel)

    def remove_status_item(self, component):
        self.status_area_panel.remove(component)

    def get_status_text(self):
        return self.status_label.cget('text')

    def set_status_text(self, text):
        if not text:
            return
        self.status_label.config(text=text)
        self.transition_message()

    def transition_message(self):
        pass

    def clear_status_messages(self):
        self.status_label.config(text='')
        self.message_queue.clear()
        self.root.update_idletasks()

    def add_message_to_queue(self, message):
        if not message:
            return
        self.message_queue.append(message)

    def get_tooltip_text(self):
        tooltip = ''
        for i, message in enumerate(reversed(self.message_queue)):
            if i > 0:
                tooltip += '\n'
            tooltip += message

        return tooltip


class FadeTimer(Timer):
    def __init__(self):
        super().__init__(5000)

    def action(self):
        pass


class AnimationDelayTimer(Timer):
    def __init__(self):
        super().__init__(5000)


class FlashTimer(Timer):
    MAX_FLASH_COUNT = 6

    def __init__(self):
        super().__init__(500)
        self.flash_count = 0
        self.default_fg_color = None

    def action(self):
        if self.flash_count < self.MAX_FLASH_COUNT:
            self.contrast_status_label_colors()
            self.flash_count += 1
        else:
            self.stop()

    def stop(self):
        super().stop()
        self.revert_label_colors()
        self.flash_count = 0

    def create_contrasting_color(self, color):
        if not self.default_fg_color:
            self.default_fg_color = self.status_label.cget('fg')

        red = int(color[1:3], 16)
        green = int(color[3:5], 16)
        blue = int(color[5:], 16)

        return f'#{255 - red:02x}{255 - green:02x}{255 - blue:02x}'

    def contrast_status_label_colors(self):
        self.status_label.config(fg=self.create_contrasting_color(self.status_label.cget('fg')))

    def revert_label_colors(self):
        self.status_label.config(fg=self.default_fg_color)


class StatusPanel(tk.Frame):
    def __init__(self, component, add_border=True):
        super().__init__()
        if add_border:
            self.borderwidth = 1
            self.relief=tk.GROOVE

        self.add(component)

    def get_preferred_size(self):
        return self.winfo_reqsize()


if __name__ == '__main__':
    status_bar = StatusBar()
