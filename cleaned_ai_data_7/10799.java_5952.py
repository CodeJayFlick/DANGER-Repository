import pygame
from pygame.locals import *

class VisualGraphPopupMousePlugin:
    def handle_popup(self, e):
        viewer = self.get_viewer(e)
        popup = PySimpleGUI.popup("Your popup content", "Title")
        popup.Show()

    def get_viewer(self, e):
        return e.source

# usage example
plugin = VisualGraphPopupMousePlugin()
pygame.event.post(MouseEvent(0, 0, plugin))
