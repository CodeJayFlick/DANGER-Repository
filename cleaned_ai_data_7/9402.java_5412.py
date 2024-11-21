class KeyBindingPrecedence:
    """An enum that holds the values for order of keybinding precedence,
       in order from highest priority to lowest.
    """
    
    ReservedActionsLevel = 0
    """Actions at this level will be processed before all others, including Java components'."""
    
    KeyListenerLevel = 1
    """Actions with this precedence will be processed before key listener on Java components."""

    ActionMapLevel = 2
    """Actions with this precedence will be processed before actions on Java components."""

    DefaultLevel = 3
    """This level of precedence is the default level of precedence and gets processed after 
       Java components' key listeners and actions."""
