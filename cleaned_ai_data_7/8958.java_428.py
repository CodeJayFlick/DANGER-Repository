class VTControllerListener:
    def session_changed(self, session):
        pass  # implement this method in your subclass

    def match_selected(self, match_info=None):
        pass  # implement this method in your subclass

    def session_updated(self, ev):
        pass  # implement this method in your subclass

    def markup_item_selected(self, markup_item=None):
        pass  # implement this method in your subclass

    def options_changed(self, options):
        pass  # implement this method in your subclass

    def disposed(self):
        pass  # implement this method in your subclass
