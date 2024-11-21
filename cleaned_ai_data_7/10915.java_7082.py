from collections import defaultdict, deque
import datetime

class TestVertexTooltipProvider:
    def __init__(self):
        self.tooltip_trigger = False
        self.shown_tooltips_by_vertex = defaultdict(list)

    def get_tooltip(self, v):
        name = v.name
        text = f"This is a tooltip for {name}"
        spy = SpyTooltipLabel(text)
        self.shown_tooltips_by_vertex[name].append(spy)
        self.tooltip_trigger = True
        return spy

    def get_tooltip(self, v, e):
        name = v.name
        text = f"This is a tooltip for {name} and edge {e}"
        spy = SpyTooltipLabel(text)
        self.shown_tooltips_by_vertex[name].append(spy)
        self.tooltip_trigger = True
        return spy

    def get_tooltip_text(self, v, e):
        name = v.name
        text = f"This is a tooltip string for {name} @ {datetime.datetime.now()}"
        spy = SpyTooltipText(text)
        self.shown_tooltips_by_vertex[name].append(spy)
        self.tooltip_trigger = True
        return text

    def get_shown_tooltips(self, v):
        return list(self.shown_tooltips_by_vertex[v.name])

    def is_tooltip_triggered(self):
        return self.tooltip_trigger

    def clear_tooltip_triggered(self):
        self.tooltip_trigger = False


class SpyTooltip:
    def get_tooltip_as_text(self):
        pass  # Abstract method


class SpyTooltipText(SpyTooltip):
    def __init__(self, text):
        self.text = text

    def get_tooltip_as_text(self):
        return self.text


class SpyTooltipLabel(GDHtmlLabel, SpyTooltip):
    def __init__(self, text):
        super().__init__()
        self.setText(text)
        self.setOpaque(True)
        self.setBackground(Color(0.5, 0.2, 0).darker())
        self.setPreferredSize((200, 100))

    def get_tooltip_as_text(self):
        return self.getText()
