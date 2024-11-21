class GComponent:
    HTML_DISABLE_STRING = "html.disable"

    def set_html_rendering_enabled(self, enabled):
        self.set_html_rendering_flag(self, enabled)

    @property
    def html_rendering_enabled(self):
        prop = getattr(self, 'getClientProperty', lambda x: None)(HTML_DISABLE_STRING)
        return prop is None or prop != True

    @staticmethod
    def warn_about_html_text(text):
        if text.lower().startswith("<html>"):
            print(f"Warning: HTML text detected in non-HTML component: {text}")

    @staticmethod
    def set_html_rendering_flag(comp, enabled):
        comp.putClientProperty(HTML_DISABLE_STRING, None if enabled else True)
