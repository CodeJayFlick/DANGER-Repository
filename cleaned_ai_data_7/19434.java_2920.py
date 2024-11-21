class PreScriptLoadEvent:
    def __init__(self, scripts):
        self.scripts = scripts

    @property
    def handlers(self):
        return _handlers


_handlers = HandlerList()


def get_handler_list():
    return _handlers


def get_scripts(self):
    return self.scripts


class Config:
    pass


from typing import List

class HandlerList:
    pass


import java.util.List  # This line is not necessary in Python
