import tkinter as tk
from tkinter import filedialog
from PIL import ImageTk, Image

class SetVertexMostRecentColorAction:
    def __init__(self, controller, vertex):
        self.controller = controller
        self.vertex = vertex
        self.color_icon = None
        self.choose_color_action = None
        self.clear_color_action = None
        
        super().__init__("Set Graph Vertex Color", "FunctionGraphPlugin")
        
        description = "Set this block's background color"
        self.setDescription(description)
        
        self.color_icon = ImageTk.PhotoImage(Image.new('RGB', (12, 12), (189, 221, 252)))
        
        blank_icon = tk.PhotoImage(file='images/blank.png')
        paint_brush_image = Image.open("images/paintbrush.png")
        scaled_brush = paint_brush_image.resize((16, 16))
        brush_icon = ImageTk.PhotoImage(scaled_brush)
        
        point = self.get_lower_left_icon_offset(blank_icon, self.color_icon)
        translate_icon = tk.Label(self, image=translate_icon)
        translate_icon.image = translate_icon
        
        multi_icon.add(translate_icon)
        
        point = self.get_right_icon_offset(blank_icon, brush_icon)
        translate_icon = tk.Label(self, image=brush_icon)
        translate_icon.image = translate_icon
        multi_icon.add(translate_icon)
        
        self.color_icon = multi_icon
        
        toolbar_data = tk.Toplevel()
        toolbar_data.iconbitmap(self.color_icon)
        
        self.create_actions()

    def get_toolbar_icon(self):
        return self.color_icon

    def create_actions(self):
        choose_color_action = DockingAction("Set Vertex Color", "FunctionGraphPlugin")
        choose_color_action.actionPerformed = lambda context: 
            color_provider = controller.getColorProvider()
            old_color = vertex.getBackgroundColor()
            new_color = color_provider.getColorFromUser(old_color)
            
            if new_color is None:
                return  # cancelled
            elif old_color == new_color:
                return  # same color
            
            color_provider.setVertexColor(vertex, new_color)

        choose_color_action.menu_bar_data = tk.MenuData(["Choose New Color"], ImageTk.PhotoImage(Image.open("images/palette.png")))
        
        clear_color_action = DockingAction("Clear Vertex Color", "FunctionGraphPlugin")
        clear_color_action.actionPerformed = lambda context: 
            color_provider = controller.getColorProvider()
            color_provider.clearVertexColor(vertex)

        choose_color_action.menu_bar_data = tk.MenuData(["Clear Background Color"], ImageTk.PhotoImage(Image.open("images/palette.png")))
        
    def dispose(self):
        super().dispose()
        self.choose_color_action.dispose()
        self.clear_color_action.dispose()

    def get_lower_left_icon_offset(self, primary_icon, overlay_icon):
        return (0, primary_icon.height - overlay_icon.height)

    def get_right_icon_offset(self, primary_icon, overlay_icon):
        return (primary_icon.width - overlay_icon.width, 0)

    def actionPerformed(self, context):
        color_provider = controller.getColorProvider()
        color_provider.setVertexColor(vertex, color_provider.getMostRecentColor())

    def create_separator(self):
        pass

    def get_action_list(self, context):
        action_list = []
        
        for recent_color in controller.getRecentColors():
            action_list.append(SetVertexColorAction(vertex, recent_color))
            
        return action_list + [self.choose_color_action, self.clear_color_action]

class SetVertexColorAction(DockingAction):
    def __init__(self, vertex, color):
        super().__init__("Set Vertex Color", "")
        
        this.vertex = vertex
        this.color = color
        
        menu_bar_data = tk.MenuData(["Select Color"], ImageTk.PhotoImage(Image.new('RGB', (12, 12), self.color)))
        
    def actionPerformed(self, context):
        color_provider = controller.getColorProvider()
        color_provider.setVertexColor(vertex, self.color)
