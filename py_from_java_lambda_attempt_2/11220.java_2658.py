Here is a translation of the provided Java code into equivalent Python:

```Python
import tkinter as tk
from tkinter import font as tkfont
from tkinter import colorchooser

class AbstractDetailsPanel:
    MIN_WIDTH = 700
    LEFT_COLUMN_WIDTH = 150
    RIGHT_MARGIN = 30
    
    def __init__(self):
        self.text_label = None
        self.scrollpane = None
        
    def create_field_attributes(self, font_family='Tahoma', font_size=11, bold=True, color=None):
        if not color:
            color = 'black'
        
        return {
            'font-family': font_family,
            'font-size': str(font_size),
            'bold': bool(bold),
            'color': color
        }
    
    def clear(self):
        self.text_label.config(text='')
    
    def create_main_panel(self, master=None):
        if not master:
            master = tk.Tk()
        
        frame = tk.Frame(master)
        frame.pack(fill='both', expand=True)

        self.text_label = tk.Label(frame, text='', wraplength=self.MIN_WIDTH - self.LEFT_COLUMN_WIDTH)
        self.text_label.pack(side=tk.TOP, fill='x')

    def insert_row_title(self, buffer, row_name):
        buffer.append('<TR>')
        buffer.append('<TD VALIGN="TOP">')
        buffer.append(row_name + ': ')
        buffer.append('</TD>')

    def insert_row_value(self, buffer, value, attributes):
        buffer.append('<TD VALIGN="TOP" WIDTH="80%">')
        buffer.append(value)
        buffer.append('</TD>')
        buffer.append('</TR>')

    def insert_html_string(self, buffer, string, attributes):
        if not string:
            return
        
        buffer.append('<FONT COLOR="#' + str(attributes['color']) + '">')
        buffer.append(string)
        buffer.append('</FONT>')


# Example usage
if __name__ == '__main__':
    panel = AbstractDetailsPanel()
    
    master = tk.Tk()

    panel.create_main_panel(master)

    text_buffer = []

    row_name = 'Row Name'
    value = 'Value'

    attributes = panel.create_field_attributes(bold=True, color='blue')

    buffer = ''.join(text_buffer)
    panel.insert_row_title(buffer, row_name)
    panel.insert_html_string(buffer + '<TD VALIGN="TOP" WIDTH="80%">', value, attributes)

    master.mainloop()
```

Please note that Python does not have direct equivalents for Java's Swing and AWT libraries. This code uses the Tkinter library to create a simple GUI with labels and text boxes.