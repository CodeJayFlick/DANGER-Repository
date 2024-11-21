import tkinter as tk
from tkinter import messagebox

class View:
    def __init__(self):
        self.model = PresentationModel(album_dataset())

    def save_to_pmod(self):
        print("Save data to PresentationModel")
        self.model.artist = txt_artist.get()
        self.model.title = txt_title.get()
        self.model.is_classical = chk_classical.get()

    def load_from_pmod(self):
        print("Load data from PresentationModel")
        txt_artist.set(self.model.artist)
        txt_title.set(self.model.title)
        chk_classical.set(self.model.is_classical)

    def create_view(self):
        root = tk.Tk()
        root.title("Album")

        b1 = tk.Frame(root, bg="white", width=500, height=300)
        b1.pack()

        album_list = tk.Listbox(b1, width=20, height=10)
        for item in self.model.album_list:
            album_list.insert(tk.END, item)

        def on_mouse_click(event):
            selected_index = album_list.curselection()[0]
            model.set_selected_album_number(selected_index + 1)
            load_from_pmod()

        album_list.bind("<Double-Button-1>", on_mouse_click)

        b2 = tk.Frame(root, bg="white", width=500, height=300)
        b2.pack()

        txt_artist = tk.Entry(b2, width=20, height=10)
        txt_title = tk.Entry(b2, width=20, height=10)

        chk_classical = tk.BooleanVar()
        chk_classical.set(False)
        chk_classical_button = tk.Checkbutton(b2, variable=chk_classical)

        def on_chk_classical_click():
            if not chk_classical.get():
                txt_composer.delete(0, tk.END)
            else:
                txt_composer.config(state="normal")

        chk_classical_button.bind("<Button-1>", lambda event: on_chk_classical_click())

        apply = tk.Button(b2, text="Apply", command=lambda: [save_to_pmod(), load_from_pmod()])
        cancel = tk.Button(b2, text="Cancel", command=load_from_pmod)

        b2.pack()

        root.geometry("500x300+200+200")
        root.mainloop()
