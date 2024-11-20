Here is the translation of the Java code into Python:

```Python
class MatchMarkupStatusRenderer:
    DISABLED_ICON = ResourceManager().get_disabled_icon("images/ledgreen.png", 50)
    APPLIED_BASE_ICON = ResourceManager().load_image("images/ledgreen.png", 8, 8)
    REJECTED_BASE_ICON = ResourceManager().load_image("images/ledpurple.png", 8, 8)
    NOT_APPLIED_BASE_ICON = ResourceManager().load_image("images/ledorange.png", 8, 8)
    IGNORED_BASE_ICON = ResourceManager().load_image("images/ledblue.png", 8, 8)
    ERROR_BASE_ICON = ResourceManager().load_image("images/ledred.png", 8, 8)

    NOT_APPLIED_ICON = TranslateIcon(NOT_APPLIED_BASE_ICON, 0, 4)
    APPLIED_ICON = TranslateIcon(APPLIED_BASE_ICON, 9, 4)
    REJECTED_ICON = TranslateIcon(REJECTED_BASE_ICON, 18, 4)
    IGNORED_ICON = TranslateIcon(IGNORED_BASE_ICON, 27, 4)
    ERROR_ICON = TranslateIcon(ERROR_BASE_ICON, 36, 4)

    DISABLED_NOT_APPLIED_ICON = TranslateIcon(DISABLED_ICON, 0, 4)
    DISABLED_APPLIED_ICON = TranslateIcon(DISABLED_ICON, 9, 4)
    DISABLED_REJECTED_ICON = TranslateIcon(DISABLED_ICON, 18, 4)
    DISABLED_IGNORED_ICON = TranslateIcon(DISABLED_ICON, 27, 4)
    DISABLED_ERROR_ICON = TranslateIcon(DISABLED_ICON, 36, 4)

    def get_table_cell_renderer_component(self, data):
        renderer = super().get_table_cell_renderer_component(data)
        value = data.get_value()
        table = data.get_table()
        is_selected = data.is_selected()

        self.set_text("")
        self.set_horizontal_alignment(CENTER)
        match = VTMatch(value)

        association = match.get_association()
        if not is_selected:
            renderer.set_background_color(self.get_background_color(association, table))

        markup_status = association.get_markup_status()
        icon = MultiIcon([EmptyIcon(36, 16)])
        if markup_status.has_unexamined_markup():
            icon.add_icon(NOT_APPLIED_ICON)
        else:
            icon.add_icon(DISABLED_NOT_APPLIED_ICON)

        if markup_status.has_applied_markup():
            icon.add_icon(APPLIED_ICON)
        else:
            icon.add_icon(DISABLED_APPLIED_ICON)

        if markup_status.has_rejected_markup():
            icon.add_icon(REJECTED_ICON)
        else:
            icon.add_icon(DISABLED_REJECTED_ICON)

        if (markup_status.has_dont_know_markup() or markup_status.has_dont_care_markup()):
            icon.add_icon(IGNORED_ICON)
        else:
            icon.add_icon(DISABLED_IGNORED_ICON)

        if markup_status.has_errors():
            icon.add_icon(ERROR_ICON)
        else:
            icon.add_icon(DISABLED_ERROR_ICON)

        self.set_icon(icon)
        self.set_tooltip_text(self.get_description(markup_status))
        return renderer

    def get_description(self, status):
        buf = StringBuffer("<html>")
        if not status.is_initialized():
            buf.append("Match has not been accepted; unknown markup status")
            return buf.toString()

        icon = DISABLED_ICON
        message = "Has one or more 'Unexamined' markup items"
        font_color = "gray"
        if status.has_unexamined_markup():
            icon = NOT_APPLIED_BASE_ICON
            font_color = "black"

        buf.append("<img src=\"{}\" />".format(icon.get_description()))
        buf.append("<font color={}>{}<font></br>".format(font_color, message))

        icon = DISABLED_ICON
        message = "Has one or more 'Applied' markup items"
        font_color = "gray"
        if status.has_applied_markup():
            icon = APPLIED_BASE_ICON
            font_color = "black"

        buf.append("<img src=\"{}\" />".format(icon.get_description()))
        buf.append("<font color={}>{}<font></br>".format(font_color, message))

        icon = DISABLED_ICON
        message = "Has one or more 'Rejected' markup items to apply"
        font_color = "gray"
        if status.has_rejected_markup():
            icon = REJECTED_BASE_ICON
            font_color = "black"

        buf.append("<img src=\"{}\" />".format(icon.get_description()))
        buf.append("<font color={}>{}<font></br>".format(font_color, message))

        icon = DISABLED_ICON
        message = "Has one or more 'Ignored (Don't Know or Don't Care)' markup items"
        font_color = "gray"
        if status.has_dont_care_markup() or status.has_dont_know_markup():
            icon = IGNORED_BASE_ICON
            font_color = "black"

        buf.append("<img src=\"{}\" />".format(icon.get_description()))
        buf.append("<font color={}>{}<font></br>".format(font_color, message))

        icon = DISABLED_ICON
        message = "Has one or more 'Error' markup items"
        font_color = "gray"
        if status.has_errors():
            icon = ERROR_BASE_ICON
            font_color = "black"

        buf.append("<img src=\"{}\" />".format(icon.get_description()))
        buf.append("<font color={}>{}<font></br>".format(font_color, message))

        return buf.toString()

    def get_filter_string(self, t, settings):
        association = t.get_association()
        markup_status = association.get_markup_status()
        html_description = self.get_description(markup_status)
        raw = HTMLUtilities.from_html(html_description)
        return raw
```

Please note that the above Python code is a direct translation of your Java code. However, it may not work as expected because some classes and methods in the original Java code are missing or have different implementations in Python.