import tkinter as tk
from datetime import datetime
import time


class DigitalClock:
    def __init__(self, master):
        self.master = master
        self.master.title("Digital Clock")

        self.is_24_hour_format = True

        self.time_label = tk.Label(master, font=('calibri', 40, 'bold'), bg='black', fg='white')
        self.time_label.pack(anchor='center')

        self.date_label = tk.Label(master, font=('calibri', 20), bg='black', fg='white')
        self.date_label.pack(anchor='center')

        self.alarm_time = None

        self.alarm_label = tk.Label(master, font=('calibri', 20), bg='black', fg='white')
        self.alarm_label.pack(anchor='center')

        self.alarm_entry = tk.Entry(master, font=('calibri', 20))
        self.alarm_entry.pack(anchor='center')
        self.alarm_entry.insert(0, "HH:MM")

        self.set_alarm_button = tk.Button(master, text="Set Alarm", command=self.set_alarm)
        self.set_alarm_button.pack(anchor='center')

        self.toggle_format_button = tk.Button(master, text="Toggle 12/24 Hour", command=self.toggle_format)
        self.toggle_format_button.pack(anchor='center')

        self.update_time()

    def update_time(self):
        current_time = datetime.now()
        time_format = "%H:%M:%S" if self.is_24_hour_format else "%I:%M:%S %p"
        formatted_time = current_time.strftime(time_format)

        self.time_label.config(text=formatted_time)
        self.date_label.config(text=current_time.strftime("%A, %B %d, %Y"))

        if self.alarm_time == formatted_time:
            self.alarm_label.config(text="ALARM! Time's up!", fg='red')

        self.master.after(1000, self.update_time)  # Update every second

    def set_alarm(self):
        alarm_input = self.alarm_entry.get()
        if self.validate_alarm(alarm_input):
            self.alarm_time = alarm_input
            self.alarm_label.config(text=f"Alarm set for {self.alarm_time}", fg='white')
        else:
            self.alarm_label.config(text="Invalid time format!", fg='red')

    def validate_alarm(self, alarm_input):
        try:
            time.strptime(alarm_input, "%H:%M")
            return True
        except ValueError:
            return False

    def toggle_format(self):
        self.is_24_hour_format = not self.is_24_hour_format
        self.update_time()


if __name__ == "__main__":
    root = tk.Tk()
    clock = DigitalClock(root)
    root.geometry("400x300")
    root.config(bg='black')
    root.mainloop()