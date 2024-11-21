Here is the translation of the Java code to Python:

```Python
class BungeeConverter:
    HAS_INSERTION_SUPPORT = hasattr(net.md_5.bungee.api.chat.BaseComponent, 'setInsertion')
    HAS_FONT_SUPPORT = hasattr(net.md_5.bungee.api.chat.BaseComponent, 'setFont')

    def convert(origin):
        base = net.md_5.bungee.api.chat.TextComponent(origin.text)

        if origin.bold:
            base.setBold(True)
        if origin.italic:
            base.setItalic(True)
        if origin.underlined:
            base.setUnderlined(True)
        if origin.strikethrough:
            base.setStrikethrough(True)
        if origin.obfuscated:
            base.setObfuscated(True)

        if origin.color is not None:
            base.setColor(origin.color)

        if HAS_INSERTION_SUPPORT and origin.insertion is not None:
            base.setInsertion(origin.insertion)

        if origin.clickEvent is not None:
            click_event = net.md_5.bungee.api.chat.ClickEvent(net.md_5.bungee.api.chat.ClickEvent.Action[origin.clickEvent.action.spigotName], origin.clickEvent.value)
            base.setClickEvent(click_event)

        if origin.hoverEvent is not None:
            hover_event = net.md_5.bungee.api.chat.HoverEvent(net.md_5.bungee.api.chat.HoverEvent.Action[origin.hoverEvent.action.spigotName], convert(ChatMessages.parse(origin.hoverEvent.value)))
            base.setHoverEvent(hover_event)

        if origin.font is not None and HAS_FONT_SUPPORT:
            base.setFont(origin.font)

        return base

    def convert(origins):
        return [convert(origin) for origin in origins]
```

Please note that Python does not have direct equivalent of Java's `@SuppressWarnings("null")` annotation. The null checks are still necessary to avoid potential errors.