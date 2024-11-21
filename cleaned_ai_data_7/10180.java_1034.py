class DoNotContinue:
    def __init__(self):
        pass

DoNotContinue = type('DoNotContinue', (), {})
@DoNotContinue
def do_not_continue():
    """marker interface"""
    pass
