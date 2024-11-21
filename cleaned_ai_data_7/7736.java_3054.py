from tkinter import *
import collections

class FilterDialog:
    def __init__(self, vertex_buttons: list, edge_buttons: list):
        self.vertex_buttons = vertex_buttons
        self.edge_buttons = edge_buttons
        
        # Create a Tkinter window with title "Filters"
        self.root = Toplevel()
        self.root.title("Filters")
        
        # Add the panel to the root window
        self.panel = Frame(self.root)
        self.panel.pack(fill=BOTH, expand=True)

    def create_panel(self):
        if not self.vertex_buttons:
            return

        vertex_frame = Frame(self.panel)
        vertex_frame.pack(fill=X)
        Label(vertex_frame, text="Vertex Filters", borderwidth=2).pack(side=LEFT)
        
        for button in self.vertex_buttons:
            button.pack(side=LEFT)

    def run(self):
        # Create the panel
        self.create_panel()
        
        # Start the Tkinter event loop
        self.root.mainloop()

# Example usage:
if __name__ == "__main__":
    vertex_filters = [Button(text="Filter 1"), Button(text="Filter 2")]
    edge_filters = [Button(text="Edge Filter 1"), Button(text="Edge Filter 2")]

    dialog = FilterDialog(vertex_filters, edge_filters)
    dialog.run()
