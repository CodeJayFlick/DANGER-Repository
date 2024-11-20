Here is the translation of the Java code into Python:

```Python
import time
from PIL import ImageTk as tk

class FilterIconFlashTimer:
    MINIMUM_TIME_BETWEEN_FLASHES = 20000
    MAX_FLASH_COUNT = 10

    def __init__(self, base_icon, filtered_icon, filter_dialog, filter_button):
        self.base_icon = base_icon
        self.filtered_icon = filtered_icon
        self.filter_dialog = filter_dialog
        self.filter_button = filter_button
        self.flash_count = 0
        self.last_flash_time = time.time()
        self.addActionListener(self)

    def actionPerformed(self, event):
        if not self.filter_dialog.is_filtered():
            self.stop()
            return

        if self.flash_count < self.MAX_FLASH_COUNT:
            self.change_icon()
            self.flash_count += 1
        else:
            self.stop()
            self.stall_animation()

    def restart(self):
        current_time = time.time()
        if current_time - self.last_flash_time < self.MINIMUM_TIME_BETWEEN_FLASHES:
            return

        self.flash_count = 0
        super().restart()

    def stop(self):
        super().stop()
        self.restore_base_icon()
        self.flash_count = 0

    def change_icon(self):
        current_icon = self.filter_button['image']
        if current_icon == self.filtered_icon:
            self.filter_button['image'] = tk.PhotoImage(file='images/EmptyIcon16.gif')
        else:
            self.filter_button['image'] = self.filtered_icon

    def restore_base_icon(self):
        if self.filter_dialog.is_filtered():
            self.filter_button['image'] = self.filtered_icon
        else:
            self.filter_button['image'] = self.base_icon

    def stall_animation(self):
        self.last_flash_time = time.time()
```

Please note that this Python code is not a direct translation of the Java code. It's more like an equivalent implementation in Python, with some differences due to language-specific features and limitations.