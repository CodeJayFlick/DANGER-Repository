import logging
from typing import Set

class SettingsFragment:
    def __init__(self):
        self.activity = None  # type: Activity
        self.application = None  # type: WalletApplication
        self.config = None  # type: Configuration
        self.pm = None  # type: PackageManager

        self.handler = Handler()
        self.background_thread = None  # type: Thread
        self.background_handler = None  # type: Handler

    def on_attach(self, activity):
        super().onAttach(activity)
        self.activity = activity
        self.application = WalletApplication.get_instance()
        self.config = application.get_configuration()
        self.pm = activity.get_package_manager()

    def on_create(self, savedInstanceState=None):
        super().onCreate(savedInstanceState)

        preferences = PreferenceFragment().load_preferences(R.xml.preference_settings)

        background_thread = Thread(target=self.background_handler.post)
        background_thread.start()
        self.background_handler = Handler(background_thread.get_looper())

        sync_mode_preference = find_preference(Configuration.PREFS_KEY_SYNC_MODE)
        if not application.full_sync_capable():
            remove_or_disable_preference(sync_mode_preference)

        trusted_peer_preference = EditTextPreference(find_preference(Configuration.PREFS_KEY_TRUSTED_PEERS))
        trusted_peer_preference.set_on_preference_change_listener(self)
        trusted_peer_preference.set_dialog_message(
            f"{getString(R.string.preferences_trusted_peer_dialog_message)}\n\n"
            f"{getString(R.string.preferences_trusted_peer_dialog_message_multiple)}"
        )

        own_name_preference = find_preference(Configuration.PREFS_KEY_OWN_NAME)
        own_name_preference.set_on_preference_change_listener(self)

        bluetooth_address_preference = EditTextPreference(find_preference(Configuration.PFS_KEY_BLUETOOTH_ADDRESS))
        bluetooth_address_preference.set_on_preference_change_listener(self)
        input_filter_all_caps = InputFilter.AllCaps(Locale.US) if Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1 else None
        length_filter_max_length = lambda s: len(s) <= BLUETOOTH_ADDRESS_LENGTH
        hex_restrictor = RestrictToHex()
        bluetooth_address_preference.get_edit_text().set_filters([input_filter_all_caps, length_filter_max_length, hex_restrictor])
        bluetooth_address_preference.get_edit_text().add_text_watcher(colon_format)

    def on_destroy(self):
        bluetooth_address_preference.get_edit_text().remove_text_watcher(colon_format)
        bluetooth_address_preference.set_on_preference_change_listener(None)
        own_name_preference.set_on_preference_change_listener(None)
        trusted_peer_only_preference.set_on_preference_change_listener(None)
        trusted_peer_preference.set_on_preference_change_listener(None)

    def on_preference_change(self, preference: Preference, new_value):
        self.handler.post(lambda: update_trusted_peers() if preference == trusted_peer_preference else
                          (update_own_name() if preference == own_name_preference else
                           (update_bluetooth_address() if preference == bluetooth_address_preference else None)))

    def update_trusted_peers(self):
        trusted_peers = config.get_trusted_peers()
        if not trusted_peers:
            trusted_peer_preference.set_summary(R.string.preferences_trusted_peer_summary)
            trusted_peer_only_preference.setEnabled(False)
        else:
            trusted_peer_preference.set_summary(R.string.preferences_trusted_peer_resolve_progress)
            trusted_peer_only_preference.setEnabled(True)

    def update_own_name(self):
        own_name = config.get_own_name()
        if not own_name:
            own_name_preference.set_summary(get_text(R.string.preferences_own_name_summary))
        else:
            own_name_preference.set_summary(own_name)

    def update_bluetooth_address(self):
        bluetooth_adapter = BluetoothAdapter.getDefault_adapter()
        if bluetooth_adapter is None:
            remove_or_disable_preference(bluetooth_address_preference)
        elif (bluetooth_address := Bluetooth.get_address(bluetooth_adapter)) is not None:
            bluetooth_address_preference.set_summary(bluetooth_address)
            bluetooth_address_preference.setEnabled(False)

    def append_to_trusted_peer_summary(self, line):
        synchronized(trusted_peer_preference) as trusted_peer:
            summary = trusted_peer.get_summary()
            if summary == get_text(R.string.preferences_trusted_peer_resolve_progress):
                summary = ""
            else:
                summary += "\n"
            trusted_peer.set_summary(summary + line)

    def remove_or_disable_preference(self, preference: Preference):
        if Build.VERSION.SDK_INT >= Build.VERSION_CODES.O:
            parent = preference.getParent()
            parent.removePreference(preference)
        else:
            preference.setEnabled(False)


class RestrictToHex(InputFilter):
    def filter(self, source: str, start: int, end: int, dest: Spanned, dstart: int, dend: int) -> str:
        result = ""
        for i in range(start, end):
            c = source[i]
            if (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F') or c == ':':
                result += c
        return result


class TextWatcher:
    def after_text_changed(self, s: Editable):
        for i in range(len(s)):
            if i % 3 == 2:
                if s[i] != ":":
                    s.insert(i, ":")
            else:
                if s[i] == ":":
                    s.delete(i, i + 1)

    def before_text_changed(self, s: str, start: int, count: int, after: int):
        pass

    def on_text_changed(self, s: str, start: int, before: int, count: int):
        pass
