import tkinter as tk
from tkinter import messagebox
import threading

class EclipseMessageUtils:
    def __init__(self):
        pass  # Prevent instantiation.

    @staticmethod
    def show_info_dialog(title, message):
        root = tk.Tk()
        shell = tk.Toplevel(root)
        MessageDialog(shell, title, message).pack()

    @staticmethod
    def show_confirm_dialog(title, message):
        ok_pressed = False

        def on_ok():
            nonlocal ok_pressed
            ok_pressed = True
            shell.destroy()

        root = tk.Tk()
        shell = tk.Toplevel(root)
        MessageDialog(shell, title, message).pack()
        button = tk.Button(shell, text="OK", command=on_ok)
        button.pack()
        root.mainloop()
        return ok_pressed

    @staticmethod
    def show_question_dialog(title, message):
        yes_pressed = False

        def on_yes():
            nonlocal yes_pressed
            yes_pressed = True
            shell.destroy()

        root = tk.Tk()
        shell = tk.Toplevel(root)
        MessageDialog(shell, title, message).pack()
        button = tk.Button(shell, text="Yes", command=on_yes)
        button.pack()
        root.mainloop()
        return yes_pressed

    @staticmethod
    def show_error_dialog(title, message):
        threading.Thread(target=lambda: messagebox.showerror("Error", message)).start()

    @staticmethod
    def show_warn_dialog(title, message):
        threading.Thread(target=lambda: messagebox.showwarning("Warning", message)).start()

    @staticmethod
    def show_wizard_error_dialog(wizard_shell, e):
        cause = e.__cause__
        if cause is not None:
            message = f"{cause.__class__.__name__}: {cause.message}"
        else:
            message = str(e)
        threading.Thread(target=lambda: messagebox.showerror("Error", message)).start()
        return message

    @staticmethod
    def info(message):
        print(f"INFO: {message}")

    @staticmethod
    def error(message, t=None):
        if t is not None:
            print(f"ERROR: {str(t)}")
        else:
            print(f"ERROR: {message}")
