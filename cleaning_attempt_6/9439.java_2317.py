import datetime as dt
from tkinter import *

class DateEditor:
    DEFAULT_DATE_FORMAT = dt.datetime.strftime("%m/%d/%Y %H:%M:%S %Z")

    def __init__(self):
        self.date = None
        self.text_field = None

    @property
    def date(self):
        return self._date

    @date.setter
    def date(self, value):
        if self._date is not None and self._date == value:
            return
        self._date = value
        if self.text_field is not None:
            self.text_field.delete(0, END)
            self.text_field.insert(END, dt.datetime.strftime(value, "%m/%d/%Y %H:%M:%S %Z"))

    def set_date_format(self, format):
        DateEditor.DEFAULT_DATE_FORMAT = format

    def get_value(self):
        return self.date

    def set_value(self, value):
        if self._date is not None and self._date == value:
            return
        self._date = value
        if self.text_field is not None:
            self.text_field.delete(0, END)
            self.text_field.insert(END, dt.datetime.strftime(value, "%m/%d/%Y %H:%M:%S %Z"))

    def set_as_text(self, text):
        try:
            date_value = dt.datetime.strptime(text, DateEditor.DEFAULT_DATE_FORMAT).date()
            self.set_value(date_value)
        except ValueError as e:
            raise ValueError(f"Can't parse text as date: {text}")

class DatePanel(Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()

        self.text_field = Entry(self, width=20)
        if self.date is not None:
            self.text_field.insert(END, dt.datetime.strftime(self.date, "%m/%d/%Y %H:%M:%S %Z"))
        else:
            self.text_field.insert(END, "")
        self.text_field.pack()

if __name__ == "__main__":
    root = Tk()
    editor = DateEditor()
    panel = DatePanel(master=root)
    panel.date = dt.datetime.now()
    root.mainloop()
