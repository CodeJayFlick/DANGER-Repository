import tkinter as tk
import time
from datetime import datetime, timedelta

# Function to update the time on the label
def update_time():
    # Get the current UTC time
    current_time_utc = datetime.utcnow()
    
    # Apply the offset for EST (UTC-5)
    est_offset = timedelta(hours=-5)
    current_time_est = current_time_utc + est_offset
    
    # Format the time as HH:MM:SS AM/PM
    current_time_str = current_time_est.strftime('%I:%M:%S %p')
    
    # Update the label with the current EST time
    clock_label.config(text=current_time_str)
    
    # Call this function again after 1000 milliseconds (1 second)
    clock_label.after(1000, update_time)

# Function to switch to light theme
def light_theme():
    root.config(bg="white")
    clock_label.config(bg="white", fg="black", bd=10, relief='solid')
    theme_button.config(bg="light gray", fg="black", text="Switch to Dark Theme", command=dark_theme)

# Function to switch to dark theme
def dark_theme():
    root.config(bg="black")
    clock_label.config(bg="black", fg="white", bd=10, relief='solid')
    theme_button.config(bg="gray", fg="white", text="Switch to Light Theme", command=light_theme)

# Set up the main window
root = tk.Tk()
root.title("EST Digital Clock with Themes")
root.geometry("400x200")
root.resizable(False, False)

# Create a label to display the time with a border (bd=10) and solid relief
clock_label = tk.Label(root, font=('calibri', 40, 'bold'), bd=10, relief='solid')
clock_label.pack(anchor='center', pady=20)

# Create a button to toggle between light and dark themes
theme_button = tk.Button(root, text="Switch to Dark Theme", font=('calibri', 12), command=dark_theme)
theme_button.pack(pady=10)

# Start with light theme by default
light_theme()

# Call the function to update the time
update_time()

# Run the Tkinter event loop
root.mainloop()
