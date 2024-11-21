class ReservedKeyBindings:
    def __init__(self):
        pass  # utils class

HELP_KEY1 = pygame.key.get_pressed([pygame.K_HELP])
HELP_KEY2 = pygame.key.get_pressed([pygame.K_F1])
HELP_INFO_KEY = (pygame.K_F1, pygame.K_CONTROL)

CONTEXT_MENU_KEY1 = (pygame.K_F10, pygame.K_SHIFT)
CONTEXT_MENU_KEY2 = (pygame.K_CONTEXT_MENU, 0)

FOCUS_INFO_KEY = (pygame.K_F2, pygame.K_CONTROL | pygame.K_ALT | pygame.K_SHIFT)
FOCUS_CYCLE_INFO_KEY = FOCUS_INFO_KEY

UPDATE_KEY_BINDINGS_KEY = (pygame.K_F4, 0)

def is_reserved_keystroke(keyStroke):
    code = keyStroke[0]
    if code in [pygame.K_LSHIFT, pygame.K_RSHIFT, pygame.K_LALT, pygame.K_RALT, 
                pygame.K_LCTRL, pygame.K_RCTRL, pygame.K_CAPSLOCK, pygame.K_TAB]:
        return True
    elif (HELP_KEY1 == keyStroke or HELP_KEY2 == keyStroke or 
          HELP_INFO_KEY == keyStroke or UPDATE_KEY_BINDINGS_KEY == keyStroke or 
          FOCUS_INFO_KEY == keyStroke or FOCUS_CYCLE_INFO_KEY == keyStroke or 
          CONTEXT_MENU_KEY1 == keyStroke or CONTEXT_MENU_KEY2 == keyStroke):
        return True
    else:
        return False

# Usage example:
reserved_key_bindings = ReservedKeyBindings()
print(is_reserved_keystroke((pygame.K_HELP, 0)))  # Returns: True
