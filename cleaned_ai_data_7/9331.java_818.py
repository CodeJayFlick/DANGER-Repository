class DefaultHelpService:
    def show_help(self, help_obj: object, info_only: bool = False, parent=None) -> None:
        if info_only:
            self.display_help_info(help_obj)
            return

    def show_help(self, url: str) -> None:
        pass  # no-op

    def exclude_from_help(self, help_object: object) -> None:
        pass  # no-op

    def is_excluded_from_help(self, help_object: object) -> bool:
        return False

    def clear_help(self, help_object: object) -> None:
        pass  # no-op

    def register_help(self, help_obj: object, help_location: str) -> None:
        pass  # no-op

    def get_help_location(self, obj: object) -> str | None:
        return None

    def help_exists(self) -> bool:
        return False

    def display_help_info(self, help_obj: object) -> None:
        msg = self.get_help_info(help_obj)
        print(msg)

    def get_help_info(self, help_obj: object) -> str:
        if help_obj is None:
            return "Help Object is null"
        
        buffy = ""
        buffy += f"HELP OBJECT: {help_obj.__class__.__name__}\n"

        if isinstance(help_obj, HelpDescriptor):
            buffy += help_obj.get_help_info()
        elif isinstance(help_obj, JButton):
            button = help_obj
            while True:
                c = getattr(button, 'getParent', lambda: None)()
                if not (isinstance(c, Window)):
                    break
            if isinstance(c, Dialog):
                buffy += f"   DIALOG: {c.getTitle()}\n"
            elif isinstance(c, Frame):
                buffy += f"   FRAME: {c.getTitle()}\n"

        return buffy

class JButton:
    def __init__(self, text: str) -> None:
        self.text = text
