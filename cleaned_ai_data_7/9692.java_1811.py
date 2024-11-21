import tkinter as tk
from tkinter import messagebox
import array

class PasswordChangeDialog:
    def __init__(self, title, server_type, server_name, user_id):
        self.root = tk.Tk()
        self.root.title(title)
        self.create_work_panel(server_type, server_name, user_id)

    def create_work_panel(self, server_type, server_name, user_id):
        workpanel = tk.Frame(self.root)
        workpanel.pack(fill="both", expand=True)

        if server_name is not None:
            label1 = tk.Label(workpanel, text=server_type + ":")
            label2 = tk.Label(workpanel, text=server_name)
            label1.grid(row=0, column=0)
            label2.grid(row=0, column=1)

        if user_id is not None:
            label3 = tk.Label(workpanel, text="User ID:")
            name_label = tk.Label(workpanel, text=user_id)
            name_label.name = "NAME-COMPONENT"
            label3.grid(row=1, column=0)
            name_label.grid(row=1, column=1)

        password_label1 = tk.Label(workpanel, text="New Password:")
        self.password_field1 = tk.Entry(workpanel, show="*")
        self.password_field2 = tk.Entry(workpanel, show="*")

        password_label1.grid(row=2, column=0)
        self.password_field1.grid(row=3, column=0)
        label4 = tk.Label(workpanel, text="Repeat Password:")
        label4.grid(row=2, column=1)
        self.password_field2.grid(row=3, column=1)

    def ok_callback(self):
        new_password = self.password_field1.get()
        if len(new_password) < 6:
            messagebox.showerror("Password Error", "Password must be a minimum of 6 characters!")
            return
        if new_password != self.password_field2.get():
            messagebox.showerror("Password Error", "Passwords do not match!")
            return

    def close(self):
        self.root.destroy()

    def dispose(self):
        self.close()
        if hasattr(self, 'new_password'):
            del self.new_password
        if hasattr(self, 'password_field1') and hasattr(self, 'password_field2'):
            for field in [self.password_field1, self.password_field2]:
                try:
                    field.grid_forget()
                except AttributeError:
                    pass

# Example usage:
dialog = PasswordChangeDialog("Password Change", "Server Type", "Server Name", "User ID")
