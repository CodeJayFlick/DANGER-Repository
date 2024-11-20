Here is a translation of the Java code into equivalent Python code:

```Python
class WalletDisclaimerFragment:
    def __init__(self):
        self.activity = None
        self.application = None
        self.message_view = None
        self.activity_view_model = None
        self.view_model = None

    def on_attach(self, context):
        super().on_attach(context)
        self.activity = context  # Assuming WalletActivity is a subclass of Context
        self.application = self.activity.get_wallet_application()

    def on_create(self, savedInstanceState):
        super().on_create(savedInstanceState)

        self.activity_view_model = ViewModelProvider(self.activity).get(WalletActivityViewModel)
        self.view_model = ViewModelProvider(self).get(WalletDisclaimerViewModel)

        self.application.blockchain_state.observe(self, lambda blockchain_state: self.update_view())
        self.view_model.get_disclaimer_enabled().observe(self, lambda disclaimer_enabled: self.update_view())

    def on_create_view(self):
        message_view = LayoutInflater.from(self.activity).inflate(R.layout.wallet.Disclaimer.fragment, None)
        message_view.set_on_click_listener(lambda v: self.activity_view_model.show_help_dialog.value(new Event<>(R.string.help_safety)))
        return message_view

    def update_view(self):
        blockchain_state = self.application.blockchain_state.get_value()
        disclaimer_enabled = self.view_model.get_disclaimer_enabled().get_value()
        show_disclaimer = disclaimer_enabled is not None and disclaimer_enabled

        progress_res_id = 0
        if blockchain_state is not None:
            impediments = set(blockchain_state.impediments)
            if Impediment.STORAGE in impediments:
                progress_res_id = R.string.blockchain_state_progress_problem_storage
            elif Impediment.NETWORK in impediments:
                progress_res_id = R.string.blockchain_state_progress_problem_network

        text = SpannableStringBuilder()
        if progress_res_id != 0:
            text.append(f"<b>{self.activity.get_string(progress_res_id)}</b>")
        if progress_res_id != 0 and show_disclaimer:
            text.append('\n')
        if show_disclaimer:
            text.append(self.activity.get_string(R.string.wallet.Disclaimer.fragment_remind_safety))
        self.message_view.set_text(text)

        view = self.get_view()
        parent = view.get_parent()
        fragment = parent if isinstance(parent, FrameLayout) else view
        fragment.set_visibility(1 if len(text) > 0 else 0)
```

Please note that Python does not have direct equivalents for Java's Android-specific classes and methods. This code is a translation of the original Java code into equivalent Python code, but it may require additional modifications to work correctly in your specific use case.

Also, please be aware that this code assumes you are using a similar architecture as the original Java code (e.g., `WalletActivity`, `WalletApplication`, etc.).