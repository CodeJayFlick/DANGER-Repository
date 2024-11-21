class ClearColorCommand:
    def __init__(self, colorizing_service):
        self.colorizing_service = colorizing_service
        self.set = None

    def apply_to(self, obj):
        if self.set and not self.set.empty():
            self.colorizing_service.clear_background_color(self.set)
        else:
            self.colorizing_service.clear_all_background_colors()
        return True

    def get_status_msg(self):
        return None

    def get_name(self):
        return "Clear Background Color"
