class DockingToolBarUtils:
    START_KEYBINDING_TEXT = "<BR><HR><CENTER>("
    END_KEYBINDNIG_TEXT = ")</CENTER>"

    def set_tool_tip_text(button, action):
        tool_tip_text = get_tool_tip_text(action)
        key_binding_text = get_key_binding_accelerator_text(button, action.get_key_binding())
        
        if key_binding_text is not None:
            button.set_tooltip_text(combine_tool_tip_text_with_key_binding(tool_tip_text, key_binding_text))
        else:
            button.set_tooltip_text(tool_tip_text)

    def combine_tool_tip_text_with_key_binding(tool_tip_text, key_binding_text):
        buffy = StringBuilder(str(tool_tip_text))

        if tool_tip_text.startswith("<HTML>"):
            end_html_tag = "</HTML>"
            close_tag_index = tool_tip_text.index(end_html_tag)
            
            if close_tag_index < 0:
                # no closing tag, which is acceptable
                buffy.append(START_KEYBINDING_TEXT + key_binding_text + END_KEYBINDNIG_TEXT)
            else:
                # remove the closing tag, put on our text, and then put the tag back on
                buffy.delete(close_tag_index, close_tag_index + len(end_html_tag) + 1)
                buffy.append(START_KEYBINDING_TEXT + key_binding_text + END_KEYBINDNIG_TEXT + end_html_tag)

            return str(buffy)

        # plain text (not HTML)
        return tool_tip_text + " (" + key_binding_text + ")"

    def get_tool_tip_text(action):
        description = action.get_description()
        
        if not StringUtils.is_empty(description):
            return description
        else:
            return action.get_name()

    def get_key_binding_accelerator_text(button, key_stroke):
        if key_stroke is None:
            return None

        builder = StringBuilder()
        modifiers = key_stroke.get_modifiers()
        
        if modifiers > 0:
            builder.append(InputEvent.get_modifiers_ex_text(modifiers))

            # The Aqua LaF does not use the '+' symbol between modifiers
            if not DockingWindowsLookAndFeelUtils.is_using_aqua_ui(button.get_ui()):
                builder.append('+')
            
        key_code = key_stroke.get_key_code()
        
        if key_code != 0:
            builder.append(KeyEvent.get_key_text(key_code))
        else:
            builder.append(str(key_stroke.get_key_char()))
        
        return str(builder)
