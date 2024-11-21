Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
from time import sleep

class ConsoleTextPane:
    CUSTOM_ATTRIBUTE_KEY = "CUSTOM_ATTRIBUTE_KEY"
    OUTPUT_ATTRIBUTE_VALUE = "OUTPUT"
    ERROR_ATTRIBUTE_VALUE = "ERROR"

    OPTIONS_NAME = "Console"
    MAXIMUM_CHARACTERS_OPTION_NAME = "Character Limit"
    TRUNCATION_FACTOR_OPTION_NAME = "Truncation Factor"
    DEFAULT_MAXIMUM_CHRS = 50000
    MINIMUM_MAXIMUM_CHRS = 1000
    MAX_UPDATE_INTERVAL_MS = 100

    DEFAULT_TRUNCATION_FACTOR = .10

    def __init__(self, tool):
        self.create_attributes()
        self.set_editable(True)

        options = tool.get_options(self.OPTIONS_NAME)
        options.add_listener(self)
        self.init_options(options)

    def set_scroll_lock(self, lock):
        self.scroll_lock = lock
        if lock:
            self.update_caret_selection_policy(lock)
        else:
            self.update_caret_selection_policy(False)

    def add_message(self, message):
        self.do_add_message(MessageWrapper(message))

    def add_partial_message(self, message):
        self.do_add_message(MessageWrapper(message))

    def add_error_message(self, message):
        self.do_add_message(ErrorMessage(message))

    def options_changed(self, tool_options, name, old_value, new_value):
        if (self.MAXIMUM_CHARACTERS_OPTION_NAME == name or
            self.TRUNCATION_FACTOR_OPTION_NAME == name):
            self.update_from_options(tool_options)

    def init_options(self, options):
        options.register_option(self.MAXIMUM_CHARACTERS_OPTION_NAME,
                                 self.DEFAULT_MAXIMUM_CHRS, None,
                                 "The maximum number of characters to display before truncating characters from the top of the console.")
        options.register_option(self.TRUNCATION_FACTOR_OPTION_NAME,
                                 self.DEFAULT_TRUNCATION_FACTOR, None,
                                 "The factor (when multiplied by the "
                                 + self.MAXIMUM_CHARACTERS_OPTION_NAME
                                 + ") by which to remove characters when truncating is necessary.")

        self.update_from_options(options)

    def update_from_options(self, options):
        new_limit = options.get_int(self.MAXIMUM_CHARACTERS_OPTION_NAME,
                                    self.DEFAULT_MAXIMUM_CHRS)
        self.truncation_factor = options.get_double(
            self.TRUNCATION_FACTOR_OPTION_NAME, self.DEFAULT_TRUNCATION_FACTOR
        )
        self.set_maximum_character_limit(new_limit)

    def set_maximum_character_limit(self, limit):
        self.maximum_character_limit = max(limit, self.MINIMUM_MAXIMUM_CHRS)

    def get_maximum_character_limit(self):
        return self.maximum_character_limit

    def update_caret_selection_policy(self, lock):
        if lock:
            caret = self.get_caret()
            if isinstance(caret, tk.DefaultCaret):
                default_caret = caret
                default_caret.set_update_policy(tk.DefaultCaret.NEVER_UPDATE)
        else:
            default_caret = self.get_caret()
            if isinstance(default_caret, tk.DefaultCaret):
                default_caret.set_update_policy(tk.DefaultCaret.ALWAYS_UPDATE)

    def do_add_message(self, new_message):
        with self.message_list_lock:
            if not self.message_list.empty():
                last_message = self.message_list.queue[0]
                if last_message.merge(new_message):
                    return
            self.message_list.put(new_message)
        self.update_manager.update()

    def set_font(self, font):
        self.create_attributes(font)
        self.update_current_text_with_new_font()
        super().set_font(font)

    def update_current_text_with_new_font(self):
        document = self.get_document()
        if not isinstance(document, tk.StyledDocument):
            return
        styled_document = document
        length = document.index("end")
        for i in range(length):
            element = styled_document.element_at(i)
            start = i
            end = element.end_index()
            i = end

            # get the name of the old AttributeSet and use that to pick the new live
            # AttributeSet that was updated.
            attribute_set = self.get_attribute_set_by_name(
                (str)element.attributes()[self.CUSTOM_ATTRIBUTE_KEY]
            )
            styled_document.set_character_attributes(start, end - start,
                                                      attribute_set, True)

    def get_attribute_set_by_name(self, attribute_set_name):
        if attribute_set_name == self.OUTPUT_ATTRIBUTE_VALUE:
            return self.output_attribute_set
        elif attribute_set_name == self.ERROR_ATTRIBUTE_VALUE:
            return self.error_attribute_set
        else:
            raise AssertionError("Unexpected attribute type for text")

    def create_attributes(self, font=None):
        self.output_attribute_set = tk.simpletag.SimpleTag()
        self.output_attribute_set.add_attribute(
            self.CUSTOM_ATTRIBUTE_KEY,
            self.OUTPUT_ATTRIBUTE_VALUE
        )
        if font is not None:
            self.output_attribute_set.add_attribute(tk.StyleConstants.FamilyName, font.family)
            self.output_attribute_set.add_attribute(tk.StyleConstants.FontSize, font.size)
            self.output_attribute_set.add_attribute(tk.StyleConstants.Italic, font.isitalic())
            self.output_attribute_set.add_attribute(
                tk.StyleConstants.Bold,
                font.bold
            )
        else:
            self.output_attribute_set.add_attribute(
                tk.StyleConstants.FamilyName,
                "monospaced"
            )
            self.output_attribute_set.add_attribute(
                tk.StyleConstants.FontSize, 12
            )
            self.output_attribute_set.add_attribute(tk.StyleConstants.Italic, True)
            self.output_attribute_set.add_attribute(tk.StyleConstants.Bold, False)

        self.error_attribute_set = tk.simpletag.SimpleTag()
        self.error_attribute_set.add_attribute(self.CUSTOM_ATTRIBUTE_KEY,
                                               self.ERROR_ATTRIBUTE_VALUE)
        if font is not None:
            self.error_attribute_set.add_attribute(
                tk.StyleConstants.FamilyName, font.family
            )
            self.error_attribute_set.add_attribute(tk.StyleConstants.FontSize, font.size)
            self.error_attribute_set.add_attribute(tk.StyleConstants.Italic, font.isitalic())
            self.error_attribute_set.add_attribute(
                tk.StyleConstants.Bold,
                font.bold
            )
        else:
            self.error_attribute_set.add_attribute(
                tk.StyleConstants.FamilyName,
                "monospaced"
            )
            self.error_attribute_set.add_attribute(tk.StyleConstants.FontSize, 12)
            self.error_attribute_set.add_attribute(tk.StyleConstants.Italic, True)
            self.error_attribute_set.add_attribute(tk.StyleConstants.Bold, False)

    def do_update(self):
        stop_ms = int(time.time() + self.MAX_UPDATE_INTERVAL_MS / 1000.0)

        # track the caret manually because removing the text where the caret is located
        # will reset the caret position to 0, even with the update police NEVER_UPDATE.
        caret_pos = self.get_caret_position()
        while not self.message_list.empty() and time.time() < stop_ms:
            msg = self.message_list.queue[0]
            if self.append_string(msg.message, msg.attributes):
                return True
        if not self.scroll_lock or self.caret_invalidated:
            # manually set the caret position because it was
            # 1) invalidated (even though scroll lock was true), or
            # 2) is tracking the bottom of the console (normal mode)
            new_doc_len = self.get_document().index("end")
            if not self.scroll_lock and caret_pos < new_doc_len:
                self.set_caret_position(new_doc_len)

    def append_string(self, message, attribute_set):
        if len(message) > self.maximum_character_limit:
            delta = len(message) - self.maximum_character_limit
            message = message[delta:]
        try:
            document = self.get_document()
            overage = document.index("end") + len(message) - self.maximum_character_limit
            if overage <= 0:
                document.insert_string(document.index("end"), message, attribute_set)
                return False

            # trim the excess text that will result when inserting the new message
            truncation_amount = int(self.maximum_character_limit * self.truncation_factor)
            doc_to_trim = min(overage + truncation_amount, document.index("end"))
            if caret_pos < doc_to_trim:
                document.delete(0, doc_to_trim)

            document.insert_string(document.index("end"), message, attribute_set)
            return True
        except tk.TclError as e:
            print(f"Unexpected exception updating text: {e}")
            return False

    def dispose(self):
        self.update_manager.dispose()

class MessageWrapper:
    def __init__(self, message):
        if not isinstance(message, str):
            raise AssertionError("Attempted to log a null message.")
        self.message = tk.StringVar(value=message)

    def get_message(self):
        return self.message.get()

    def merge(self, other):
        if not isinstance(other, MessageWrapper) or not isinstance(self, MessageWrapper):
            return False
        self.message.set(f"{self.message.get()} {other.get_message()}")
        return True

class ErrorMessage(MessageWrapper):
    pass

# Create a console text pane.
console_text_pane = ConsoleTextPane(None)

# Add messages to the console.
for i in range(10):
    if i % 2 == 0:
        message = f"Message {i}"
    else:
        message = f"Error: Message {i}"
    console_text_pane.add_message(message)
```

This Python code is a direct translation of your Java code.