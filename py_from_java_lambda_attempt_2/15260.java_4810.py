Here is a translation of the Java code into equivalent Python code:

```Python
class AboutFragment:
    def __init__(self):
        self.application = None
        self.package_manager = None

    KEY_ABOUT_VERSION = "about_version"
    KEY_ABOUT_MARKET_APP = "about_market_app"
    KEY_ABOUT_CREDITS_BITCOINJ = "about_credits_bitcoinj"

    class ApkHashFragment:
        def __init__(self):
            pass

        def onCreateDialog(self, savedInstanceState=None):
            message = None
            try:
                application = self.application  # Assuming 'application' is an instance variable
                message = WalletUtils.format_hash(application.apk_hash().toString(), 4, 0)
            except IOException as x:
                message = "n/a"
            dialog = DialogBuilder.dialog(None, R.string.about_version_apk_hash_title, message)  # Assuming 'DialogBuilder' and 'R' are modules
            dialog.single_dismiss_button(None)
            return dialog.create()

    def on_attach(self, activity):
        super().on_attach(activity)

        self.application = activity.get_application()
        self.package_manager = activity.get_package_manager()

    def onCreate(self, savedInstanceState=None):
        super().on_create(savedInstanceState)

        preferences = PreferenceFragment.add_preferences_from_resource(R.xml.preference_about)  # Assuming 'PreferenceFragment' and 'R' are modules

        package_info = self.application.package_info
        version_pref = find_preference(KEY_ABOUT_VERSION)
        version_pref.set_summary(WalletApplication.version_line(package_info))
        version_pref.on_preference_click_listener(lambda preference: new ApkHashFragment().show(get_fragment_manager(), None))

        installer = Installer.from(self.application) if Installer.else() is not None else Installer.F_DROID
        market_pref = find_preference(KEY_ABOUT_MARKET_APP)
        market_pref.set_title(R.string.about_market_app_title, installer.display_name)

        market_intent = Intent(Intent.ACTION_VIEW, Uri.parse(installer.app_store_page_for(self.application).toString()))
        if self.package_manager.resolve_activity(market_intent, 0) is not None:
            market_pref.set_intention(market_intent)
            market_pref.set_enabled(True)

        find_preference(KEY_ABOUT_CREDITS_BITCOINJ).set_title(R.string.about_credits_bitcoinj_title, VersionMessage.BITCOINJ_VERSION)


# Assuming 'WalletApplication', 'Installer', and other modules are defined elsewhere
```

Please note that this is a direct translation of the Java code into Python. However, it may not be entirely correct or idiomatic Python due to differences in syntax and semantics between the two languages.