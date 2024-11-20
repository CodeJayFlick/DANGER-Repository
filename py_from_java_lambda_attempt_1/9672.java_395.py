Here is the translation of the Java code into Python:

```Python
from javax.swing import JPanel, JComponent, BorderFactory, TitledBorder
import java.util(Optional)

class InlineComponentTitledPanel(JPanel):
    def __init__(self, title_component: Optional[JComponent], other_border: Optional[Border] = None) -> None:
        self.border = TitledBorder(InlineComponentTitledBorder(other_border, title_component))
        super().setBorder(self.border)
        self.content = JPanel()
        super().add(content)

    @property
    def get_title_component(self):
        return self.border.get_title_component()

    @get_title_component.setter
    def set_title_component(self, component: JComponent) -> None:
        existing = self.get_title_component
        if existing is not None:
            index = super().remove(existing)
            if index != -1:
                super().add(component, index)

        self.border.set_title_component(component)
        super().add(component)

    def do_layout(self):
        insets = self.get_insets()
        rect = self.get_bounds()

        comp_rect = self.border.get_component_rect(rect, insets)
        title_component = self.get_title_component
        title_component.setBounds(comp_rect)
        rect.x += insets.left
        rect.y += insets.top
        rect.width -= (insets.left + insets.right)
        rect.height -= (insets.top + insets.bottom)

        self.content.setBounds(rect)


class InlineComponentTitledBorder(TitledBorder):
    def __init__(self, other_border: Optional[Border], title_component: JComponent, justification: int, position: int) -> None:
        super().__init__()
        self.title_component = title_component
        self.justification = justification
        self.position = position

    @property
    def get_title_component(self):
        return self.title_component

    @get_title_component.setter
    def set_title_component(self, component: JComponent) -> None:
        self.title_component = component


class InlineComponentTitledPanel(JPanel):

    def __init__(self, title_component: Optional[JComponent], other_border: Optional[Border] = None) -> None:
        super().__init__()
        if other_border is not None:
            self.border = TitledBorder(InlineComponentTitledBorder(other_border, title_component))
        else:
            self.border = TitledBorder(InlineComponentTitledPanel(title_component))

    def set_other_border(self, border: Border):
        if self.border is not None:
            self.border.set_border(border)
        super().invalidate()

    @property
    def get_other_border(self) -> Optional[Border]:
        return self.border.get_border()


class InlineComponentTitledBorder(TitledBorder):

    def __init__(self, other_border: Optional[Border], title_component: JComponent, justification: int, position: int):
        super().__init__()
        self.title_component = title_component
        self.justification = justification
        self.position = position

    @property
    def get_title_component(self) -> JComponent:
        return self.title_component

    @get_title_component.setter
    def set_title_component(self, component: JComponent):
        if self.title_component is not None:
            index = super().remove(self.title_component)
            if index != -1:
                super().add(component, index)

        self.title_component = component


class InlineComponentTitledPanel(JPanel):

    @property
    def get_content(self) -> JPanel:
        return self.content

    @get_content.setter
    def set_content(self, content: Optional[JPanel]):
        if content is not None:
            super().add(content)

    def add_component(self, comp):
        return self.get_content.add(comp)


class InlineComponentTitledPanel(JPanel):

    @property
    def get_enabled(self) -> bool:
        return super().get_enabled()

    @get_enabled.setter
    def set_enabled(self, enable: Optional[bool]):
        if enable is not None:
            super().set_enabled(enable)
            self.get_content.set_enabled(enable)


class InlineComponentTitledPanel(JPanel):

    @property
    def get_remove_all(self) -> None:
        return self.get_content.remove_all()


```

Please note that Python does not support direct translation of Java code. It requires manual rewriting and adaptation to the Python syntax, semantics, and libraries.