import tkinter as tk
from tkinter import simpledialog
import os

class PopupKeyStorePasswordProvider:
    def get_key_store_password(self, keystore_path: str, password_error: bool) -> bytes | None:
        if not os.path.exists(keystore_path):
            return None
        
        while True:
            try:
                password = simpledialog.askpassword(title="Protected PKI Certificate", prompt=f"Cert File {os.path.basename(keystore_path)}")
                break
            except tk.TclError as e:
                print(f"Invalid input: {e}")
        
        if password_error and not self._verify_password(password):
            return None
        
        return bytes(password, 'utf-8')

    def _verify_password(self, password: str) -> bool:
        # This method should be implemented based on your requirements
        pass

class KeystorePasswordPrompt:
    def __init__(self, file_path: str, password_error: bool):
        self.file = file_path
        self.password_error = password_error
        self.password = None
    
    def run(self) -> None:
        root = tk.Tk()
        if self.password_error:
            error_text = "Incorrect password"
        else:
            error_text = ""
        
        dialog = simpledialog.askpassword(title="Protected PKI Certificate", prompt=f"Cert File {os.path.basename(self.file)}", initialvalue="", parent=root, error_message=error_text)
        root.withdraw()
        if dialog.get():
            self.password = bytes(dialog.get(), 'utf-8')
    
    def get_password(self) -> bytes | None:
        return self.password
    
    def clear_password(self) -> None:
        if self.password is not None:
            self.password = b''

if __name__ == "__main__":
    provider = PopupKeyStorePasswordProvider()
    prompt = KeystorePasswordPrompt("path_to_your_file", False)
    password = provider.get_key_store_password(prompt.file, prompt.password_error)
