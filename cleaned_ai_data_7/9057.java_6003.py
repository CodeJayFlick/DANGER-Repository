class TagMarkupItemTask:
    def __init__(self, session: 'VTSession', markup_items: list['VTMarkupItem'], tag: 'VTMarkupItemConsideredStatus'):
        self.markup_items = markup_items
        self.tag = tag

    @property
    def title(self):
        return f"{self.tag.name()} Markup Items"

    def do_work(self, monitor) -> bool:
        for markup_item in self.markup_items:
            if monitor.is_canceled():
                break
            markup_item.considered = self.tag
            monitor.increment_progress(1)
        return True

class VTSession:  # assume this is a Python class or module that provides the necessary functionality
    pass

class VTMarkupItemConsideredStatus:
    def __init__(self, name):
        self.name = name

class VTMarkupItem:
    def set_considered(self, status):
        pass

# Example usage:
session = ...  # assume you have a VTSession instance
markup_items = [...]  # list of VTMarkupItem instances
tag = VTMarkupItemConsideredStatus("example")
task = TagMarkupItemTask(session, markup_items, tag)
result = task.do_work(monitor)  # monitor is assumed to be an object that provides the necessary functionality for monitoring progress and cancellation
