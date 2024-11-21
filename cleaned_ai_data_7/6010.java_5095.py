import tkinter as tk
from PIL import Image, ImageDraw
import os

class ImageDialogProvider:
    def __init__(self, image_file, old_image, new_image):
        self.image_file = image_file
        self.old_image = old_image
        self.new_image = new_image
        
        # Create the main window
        self.root = tk.Tk()
        
        # Set up the work panel
        self.work_panel = tk.Frame(self.root)
        self.work_panel.pack(fill="both", expand=True)

        # Add a combo box for shapes
        self.shape_combo = tk.StringVar()
        self.shape_combo.set("Rectangle")
        shape_options = ["Rectangle", "Oval", "Arrow"]
        self.shape_menu = tk.OptionMenu(self.work_panel, self.shape_combo, *shape_options)
        self.shape_menu.pack()

        # Add a text field for debugging
        self.text_field = tk.Text(self.work_panel)
        self.text_field.pack(fill="both", expand=True)

        # Create the image panel
        self.image_label_old = tk.Label(self.work_panel)
        if old_image:
            photo = ImageTk.PhotoImage(old_image)
            self.image_label_old.config(image=photo, bg='black')
            self.image_label_old.image = photo  # keep a reference!
        else:
            self.image_label_old.config(text="Old image not found")

        self.image_label_new = tk.Label(self.work_panel)
        if new_image:
            photo = ImageTk.PhotoImage(new_image)
            self.image_label_new.config(image=photo, bg='black')
            self.image_label_new.image = photo  # keep a reference!
        else:
            self.image_label_new.config(text="New image not found")

        self.old_image_panel = tk.Frame(self.work_panel)
        self.old_image_panel.pack(side=tk.LEFT)

        self.new_image_panel = tk.Frame(self.work_panel)
        self.new_image_panel.pack(side=tk.RIGHT)

        # Add the old and new images to their panels
        self.old_image_label = tk.Label(self.old_image_panel, text="Old Image")
        self.old_image_label.pack()

        self.new_image_label = tk.Label(self.new_image_panel, text="New Image")
        self.new_image_label.pack()

        # Set up the file writer
        def write_file(image):
            try:
                image.save(self.image_file)
                print(f"Captured tool to {self.image_file}")
            except Exception as e:
                print("Error writing image file:", str(e))

        # Add a button for saving the new image
        self.save_button = tk.Button(self.work_panel, text="Save", command=lambda: write_file(new_image))
        self.save_button.pack()

    def run(self):
        self.root.mainloop()
