class HorizontalRuleAction:
    id_count = 0

    def __init__(self, owner, top_name, bottom_name):
        self.id_count += 1
        super().__init__("HorizontalRuleAction: " + str(self.id_count), owner, False)
        self.set_enabled(False)

        menu_bar_data = MenuData([f"<HTML><CENTER><FONT SIZE=2 COLOR=SILVER>{fixup_first_amp(fix_html(top_name) + '<BR>' + fix_html(bottom_name))}</FONT></CENTER>"])
        super().set_menu_bar_data(menu_bar_data)

        description = f"<HTML><CENTER><B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{fix_html(top_name)}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<HR><B>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{fix_html(bottom_name)}&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</B></CENTER>"
        super().set_description(description)

    def fixup_first_amp(self, text):
        index = text.find('&')
        if index < 0:
            return text
        else:
            return text[:index] + '&' + text[index:]

    def fix_html(self, text):
        return HTMLUtilities.escapeHTML(text)


class MenuData(list):
    pass


class ActionContext:
    pass

super().__init__()
