Here is the translation of the Java code into Python:

```Python
from abc import ABCMeta, abstractmethod
import typing as t

class GhidraComboBox(t.Generic[E]):
    def __init__(self):
        super().__init__()
        self._listeners = []
        self._doc_listeners = []
        self._set_selected_flag = False
        self._forward_enter = True
        self._default_system_enter_forwarding_action = None

    @property
    def forward_enter(self) -> bool:
        return self._forward_enter

    @forward_enter.setter
    def forward_enter(self, value: bool):
        self._forward_enter = value

    def setUI(self, ui):
        super().setUI(ui)
        editor_component = self.getEditor().getEditorComponent()
        if isinstance(editor_component, JTextField):
            text_field = (JTextField)editor_component
            text_field.addActionListener(ActionListener(lambda e: self.notify_action_listeners(e)))
            text_field.setDocument(InterceptedInputDocument())
            text_field.getDocument().addDocumentListener(DocumentListener(
                lambda e: self.notify_document_listeners(e)
            ))
        if self._default_system_enter_forwarding_action is not None:
            ActionMap(action_map=self.getActionMap()).put("enterPressed", AbstractAction(
                actionPerformed=lambda e: self.default_system_enter_forwarding_action.actionPerformed(e) if self.forward_enter else None
            ))

    def setEnterKeyForwarding(self, forward_enter):
        self._forward_enter = forward_enter

    @property
    def text(self) -> str:
        editor_component = self.getEditor().getEditorComponent()
        if isinstance(editor_component, JTextField):
            return (JTextField)(editor_component).getText()

    def setSelectedItem(self, obj: E):
        self._set_selected_flag = True
        super().setSelectedItem(obj)
        editor_component = self.getEditor().getEditorComponent()
        if isinstance(editor_component, JTextField):
            text_field = (JTextField)editor_component
            update_textfield_text_for_cleared_selection(text_field, obj)
            text_field.selectAll()
        self._set_selected_flag = False

    def setColumnCount(self, column_count: int):
        editor_component = self.getEditor().getEditorComponent()
        if isinstance(editor_component, JTextField):
            (JTextField)(editor_component).setColumns(column_count)

    @property
    def selected_item(self) -> E:
        return super().getSelectedItem()

    def clearModel(self):
        model = DefaultComboBoxModel[E](self.getModel())
        model.removeAllElements()

    def addToModel(self, obj: E):
        model = DefaultComboBoxModel[E](self.getModel())
        model.addElement(obj)

    def containsItem(self, obj: E) -> bool:
        return self.getModel().getIndexOf(obj) != -1

    @property
    def listeners(self) -> list[t.Any]:
        return self._listeners

    def addActionListener(self, l):
        self._listeners.append(l)

    def removeActionListener(self, l):
        if l in self._listeners:
            self._listeners.remove(l)

    @property
    def doc_listeners(self) -> list[t.Any]:
        return self._doc_listeners

    def addDocumentListener(self, l):
        self._doc_listeners.append(l)

    def removeDocumentListener(self, l):
        if l in self._doc_listeners:
            self._doc_listeners.remove(l)

    @property
    def default_system_enter_forwarding_action(self) -> t.Any:
        return self._default_system_enter_forwarding_action

    def notifyActionListeners(self, e: ActionEvent):
        for listener in self.listeners:
            if hasattr(listener, 'actionPerformed'):
                listener.actionPerformed(e)
            else:
                raise TypeError(f"Invalid ActionListener {listener}")

    @property
    def set_selected_flag(self) -> bool:
        return self._set_selected_flag

    @set_selected_flag.setter
    def set_selected_flag(self, value: bool):
        self._set_selected_flag = value

    def notifyDocumentListeners(self, e: DocumentEvent):
        for listener in self.doc_listeners:
            if hasattr(listener, 'insertUpdate'):
                listener.insertUpdate(e)
            elif hasattr(listener, 'changedUpdate'):
                listener.changedUpdate(e)
            elif hasattr(listener, 'removeUpdate'):
                listener.removeUpdate(e)

    def match_history(self, input: str) -> t.Optional[str]:
        if self._set_selected_flag:
            return None
        count = len(self.getModel().getElements())
        for i in range(count):
            cur = self.getModel().getElementAt(i)
            if isinstance(cur, E) and str(cur).startswith(input):
                return str(cur)

    class InterceptedInputDocument(DefaultStyledDocument):
        def __init__(self):
            super().__init__()

        @abstractmethod
        def insertString(self, offs: int, text: str, attrs: t.Any) -> None:
            if self._automated:
                self._automated = False
            else:
                editor_component = self.getEditor().getEditorComponent()
                input = (JTextField)(editor_component).getText()
                match = self.match_history(input)
                if match is not None and len(match) > len(input):
                    self._automated = True
                    (JTextField)(editor_component).setText(str(match))
                    (JTextField)(editor_component).setSelectionStart(len(input))
                    (JTextField)(editor_component).setSelectionEnd(len(match))

        @property
        def automated(self) -> bool:
            return self._automated

        @automated.setter
        def automated(self, value: bool):
            self._automated = value
```

Please note that this is a direct translation of the Java code into Python. The resulting Python code may not be idiomatic or optimized for performance.