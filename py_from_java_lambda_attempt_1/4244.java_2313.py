Here is the translation of the given Java code into Python:

```Python
import tkinter as tk
from tkinter import ttk
import string
import re

class AsciiSearchFormat:
    def __init__(self):
        self.search_type = None
        self.encoding_cb = None
        self.case_sensitive_ckb = None
        self.escape_sequences_ckb = None
        self.supported_charsets = [standardCharsets.US_ASCII, standardCharsets.UTF_8, standardCharsets.UTF_16]

    def get_tooltip(self):
        return "Interpret value as a sequence of characters."

    def get_options_panel(self):
        al = tk.Frame()
        search_type_label = ttk.Label(al, text="Encoding:")
        self.search_type = search_type_label

        encoding_cb = ttk.Combobox(al)
        for charset in self.supported_charsets:
            encoding_cb['values'].append(charset.name)
        encoding_cb.set('US-ASCII')
        al.pack(side=tk.LEFT)

        case_sensitive_ckb = tk.Checkbutton(al, text="Case Sensitive")
        case_sensitive_ckb.pack(side=tk.LEFT)

        escape_sequences_ckb = tk.Checkbutton(al, text="Escape Sequences")
        escape_sequences_ckb.pack(side=tk.LEFT)

        return al

    def uses_endianness(self):
        if self.encoding_cb.get() == standardCharsets.UTF_16:
            return True
        else:
            return False

    def get_search_data(self, input_string):
        mask_byte = 0xdf
        encoding_selection = self.encoding_cb.get()
        if encoding_selection == standardCharsets.UTF_16:
            encoding_selection = 'UTF-16BE' if is_big_endian() else 'UTF-16LE'

        if escape_sequences_ckb.instate():
            input_string = convert_escape_sequences(input_string)

        byte_array = input_string.encode(encoding_selection)
        mask_array = bytearray(len(byte_array))
        for i in range(len(byte_array)):
            if not case_sensitive_ckb.instate() and encoding_selection == standardCharsets.US_ASCII:
                if 0 <= ord(byte_array[i]) <= 26 or 0 >= ord(byte_array[i]) >= -27:
                    mask_array[i] = mask_byte
            elif not case_sensitive_ckb.instate():
                num_bytes = bytes_per_char_UTF8(ord(byte_array[i]))
                for j in range(num_bytes):
                    if encoding_selection == standardCharsets.UTF_16BE and i + 1 < len(byte_array) and byte_array[i+1] == 0:
                        mask_array[i+j*2] = mask_byte
                    elif encoding_selection == standardCharsets.UTF_16LE and i >= 1 and byte_array[i-1] == 0:
                        mask_array[i+(j-1)*2] = mask_byte

        return SearchData(input_string, bytearray(byte_array), bytearray(mask_array))

    def bytes_per_char_UTF8(self, zbyte):
        offset = 1
        while (zbyte & 0x80) != 0x00:
            zbyte <<= 1
            offset += 1
        return offset

class SearchData:
    @staticmethod
    def create_search_data(input_string, byte_array, mask_array):
        # This method is intended for UTF-8 encoding.
        # The first byte in a sequence of UTF-8 bytes can tell us how many bytes make up a char.

        pass  # Implement this method

standardCharsets = {
    'US_ASCII': string.ascii_letters,
    'UTF_8': None, 
    'UTF_16BE': None, 
    'UTF_16LE': None
}

is_big_endian = True  # Set to False for little-endian encoding.

convert_escape_sequences(input_string):
    pass  # Implement this method

# Usage:
ascii_search_format = AsciiSearchFormat()
options_panel = ascii_search_format.get_options_panel()

```

Please note that Python does not have direct equivalents of Java's `JPanel`, `ActionListener`, and other Swing components. This translation uses Tkinter, a built-in Python library for creating GUIs.

The code also assumes the existence of some methods (`convert_escape_sequences` and `SearchData.create_search_data`) which are not defined in this snippet.