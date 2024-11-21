import logging
from android.preference import PreferenceFragment
from android.app import Activity
from android.os import Bundle
from de.schildbach.wallet.ui.preference import DialogBuilder
from org.bitcoinj.crypto import DeterministicKey
from org.bitcoinj.script import Script
from org.bitcoinj.wallet import DeterministicKeyChain

class DiagnosticsFragment(PreferenceFragment):
    def __init__(self, activity: Activity) -> None:
        super().__init__()
        self.activity = activity
        self.application = activity.getApplication()
        self.config = self.application.getConfig()

    PREFS_KEY_INITIATE_RESET = "initiate_reset"
    PREFS_KEY_EXTENDED_PUBLIC_KEY = "extended_public_key"

    log = logging.getLogger(__name__)

    def onAttach(self, activity: Activity) -> None:
        super().onAttach(activity)
        self.activity = activity
        self.application = activity.getApplication()
        self.config = self.application.getConfig()

    def onCreate(self, savedInstanceState: Bundle) -> None:
        super().onCreate(savedInstanceState)

        self.addPreferencesFromResource(R.xml.preference_diagnostics)

    def onPreferenceTreeClick(self, preferenceScreen: PreferenceScreen, preference: Preference) -> bool:
        key = preference.getKey()

        if key == self.PREFS_KEY_INITIATE_RESET:
            self.handleInitiateReset()
            return True
        elif key == self.PREFS_KEY_EXTENDED_PUBLIC_KEY:
            self.handleExtendedPublicKey()
            return True

        return False

    def handleInitiateReset(self) -> None:
        dialog = DialogBuilder.dialog(self.activity, R.string.preferences_initiate_reset_title,
                                       R.string.preferences_initiate_reset_dialog_message)
        dialog.setPositiveButton(R.string.preferences_initiate_reset_dialog_positive,
                                   lambda d, which: self.log.info("manually initiated block chain reset")
                                    and BlockchainService.resetBlockchain(self.activity)
                                    and self.config.resetBestChainHeightEver()
                                    and self.config.updateLastBlockchainResetTime()
                                    and self.activity.finish())
        dialog.setNegativeButton(R.string.button_dismiss, None)
        dialog.show()

    def handleExtendedPublicKey(self) -> None:
        active_key_chain = self.application.getWallet().getActiveKeyChain()
        extended_key = active_key_chain.getWatchingKey()
        output_script_type = active_key_chain.getOutputScriptType()
        creation_time_seconds = extended_key.getCreationTimeSeconds()
        base58 = f"{extended_key.serializePubB58(Constants.NETWORK_PARAMETERS, output_script_type)}?c={creation_time_seconds}&h=bip32"
        ExtendedPublicKeyFragment.show(self.activity.getFragmentManager(), base58)
