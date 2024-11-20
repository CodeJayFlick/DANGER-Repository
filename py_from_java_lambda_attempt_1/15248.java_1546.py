Here is a translation of the Java code into equivalent Python:

```Python
import logging

class HelpDialogFragment:
    FRAGMENT_TAG = type.__name__
    KEY_MESSAGE = "message"

    @classmethod
    def page(cls, fm, message_res_id):
        new_fragment = cls.instance(message_res_id)
        new_fragment.show(fm, cls.FRAGMENT_TAG)

    @classmethod
    def instance(cls, message_res_id):
        fragment = HelpDialogFragment()
        args = {"message": message_res_id}
        fragment.set_args(args)
        return fragment

    activity = None

    @staticmethod
    def get_logger():
        logger = logging.getLogger(HelpDialogFragment.__name__)
        return logger

    def on_attach(self, context):
        super().on_attach(context)
        self.activity = (AbstractWalletActivity)(context)

    def on_create(self, savedInstanceState):
        super().on_create(savedInstanceState)
        HelpDialogFragment.get_logger().info("opening dialog %s", type.__name__)

    def on_create_dialog(self, savedInstanceState):
        args = self.get_args()
        message_res_id = args["message"]

        from html import escape
        dialog_text = escape(self.activity.getString(message_res_id))
        dialog = DialogBuilder.dialog(self.activity, 0, dialog_text)
        dialog.single_dismiss_button(None)
        return dialog.create()

class AbstractWalletActivity:
    pass

class DialogFragment:
    def show(self, fm, tag):
        raise NotImplementedError("Must be implemented by subclass")

class DialogBuilder:
    @staticmethod
    def dialog(activity, gravity, text):
        raise NotImplementedError("Must be implemented by subclass")

    @staticmethod
    def single_dismiss_button(button_text):
        raise NotImplementedError("Must be implemented by subclass")
```

Please note that this is a translation of the Java code into equivalent Python. The actual implementation details may vary depending on your specific requirements and constraints in Python, such as using different libraries or frameworks for Android-like functionality.