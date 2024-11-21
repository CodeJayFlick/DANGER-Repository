Here is a translation of the Java code into equivalent Python code:

```Python
class WalletActionsFragment:
    def __init__(self):
        self.activity = None

    def on_attach(self, context):
        super().__init__()
        self.activity = context.getattr('wallet_activity')

    def on_create_view(self, inflater, container, savedInstanceState):
        view = inflater.inflate(R.layout.wallet_actions_fragment, container, False)

        request_button = view.find(R.id.wallet_actions_request)
        request_button.set_listener(lambda v: self.activity.handle_request_coins())

        send_button = view.find(R.id.wallet_actions_send)
        send_button.set_listener(lambda v: self.activity.handle_send_coins())

        send_qr_button = view.find(R.id.wallet_actions_send_qr)
        send_qr_button.set_listener(lambda v: self.activity.handle_scan(v))
        CheatSheet.setup(send_qr_button)

        return view

    def on_resume(self):
        super().__init__()
        self.update_view()

    def update_view(self):
        show_actions = not bool(R.bool.wallet_actions_top)

        if hasattr(self, 'view'):
            parent = self.view.get_parent()
            fragment = parent if isinstance(parent, FrameLayout) else self.view
            fragment.set_visibility(1 if show_actions else 0)
```

Please note that this translation is based on the assumption that you are using a Python framework such as Kivy or Pydroid to create an Android app.