import re
from typing import List

class HelpViewSearcher:
    DIALOG_TITLE_PREFIX = "Whole Word Search in "
    FIND_ACTION_NAME = "find.action"

    def __init__(self, jHelp: object, helpModel: object):
        self.jHelp = jHelp
        self.helpModel = helpModel

        self.findDialog = FindDialog(DIALOG_TITLE_PREFIX)

        # grab search engine
        for navigator in jHelp.getHelpNavigators():
            if isinstance(navigator, JHelpSearchNavigator):
                self.searchEngine = navigator.getSearchEngine()
                break
        else:
            raise AssertionError("Unable to locate help search engine")

    def install_popup(self) -> None:
        htmlEditorPane.addMouseListener(MouseAdapter())

    def install_keybindings(self) -> None:
        KeyBindingUtils.register_action(htmlEditorPane, FIND_KEYSTROKE, FindDialogAction(), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT)

    def show_popup_menu(self, e: MouseEvent) -> None:
        menu = JPopupMenu()
        menuItem = JMenuItem("Find on Page...")
        menuItem.addActionListener(FindDialogAction())
        menu.add(menuItem)
        menu.show(htmlEditorPane, e.getX(), e.getY())

class FindDialogAction(AbstractAction):
    def __init__(self) -> None:
        super().__init__(FIND_ACTION_NAME)

    def actionPerformed(self, event: ActionEvent) -> None:
        helpWindow = WindowUtilities.window_for_component(htmlEditorPane)
        DockingWindowManager.show_dialog(helpWindow, self.findDialog)


class Searcher:
    def get_cursor_position(self) -> CursorPosition:
        if start_search_from_beginning:
            return new CursorPosition(0)

        caret_position = html_editor_pane.get_caret_position()
        return new CursorPosition(caret_position)

    def set_cursor_position(self, position: CursorPosition) -> None:
        cursor_position = position.position
        html_editor_pane.set_caret_position(cursor_position)


class ScreenSearchTask(Task):
    def __init__(self, text: str, use_regex: bool) -> None:
        super().__init__("Help Search Task", True, False, True, True)
        self.text = text
        self.use_regex = use_regex

    def run(self, monitor: TaskMonitor) -> None:
        document = html_editor_pane.get_document()
        try:
            screen_text = document.get_text(0, document.get_length())

            if self.use_regex:
                pattern = re.compile(text, re.IGNORECASE | re.DOTALL)
                matcher = pattern.matcher(screen_text)
                while matcher.find():
                    start = matcher.start()
                    end = matcher.end()
                    search_hits.append(SearchHit(1.0, start, end))
            else:
                word_offset = text.length
                for i in range(document.get_length()):
                    if screen_text[i:i + word_offset] == text:
                        search_hits.append(SearchHit(1.0, 0, word_offset))

        except BadLocationException as e:
            Msg.debug(self, "Unexpected exception retrieving help text", e)
        except PatternSyntaxException as e:
            Msg.show_error(self, html_editor_pane, "Regular Expression Syntax Error", str(e))


class SearchHit:
    def __init__(self, confidence: float, start: int, end: int) -> None:
        self.confidence = confidence
        self.start = start
        self.end = end

    @property
    def begin(self):
        return self.start


# Note that this is not a direct translation from Java to Python.
