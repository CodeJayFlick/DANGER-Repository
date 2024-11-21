class WalletActivityViewModel:
    class EnterAnimationState(enum.Enum):
        WAITING = 1
        ANIMATING = 2
        FINISHED = 3

    def __init__(self, application: Application):
        self.application = application
        self.wallet_encrypted = WalletEncryptedLiveData(self.application)
        self.wallet_legacy_fallback = WalletLegacyFallbackLiveData(self.application)

    def animate_when_loading_finished(self):
        self.do_animation = True
        self.maybe_toggle_state()

    @property
    def do_animation(self) -> bool:
        return self._do_animation

    @do_animation.setter
    def do_animation(self, value: bool):
        self._do_animation = value

    @property
    def global_layout_finished(self) -> bool:
        return self._global_layout_finished

    @global_layout_finished.setter
    def global_layout_finished(self, value: bool):
        self._global_layout_finished = value

    @property
    def balance_loading_finished(self) -> bool:
        return self._balance_loading_finished

    @balance_loading_finished.setter
    def balance_loading_finished(self, value: bool):
        self._balance_loading_finished = value

    @property
    def address_loading_finished(self) -> bool:
        return self._address_loading_finished

    @address_loading_finished.setter
    def address_loading_finished(self, value: bool):
        self._address_loading_finished = value

    @property
    def transactions_loading_finished(self) -> bool:
        return self._transactions_loading_finished

    @transactions_loading_finished.setter
    def transactions_loading_finished(self, value: bool):
        self._transactions_loading_finished = value

    def balance_loading_finished(self):
        self.balance_loading_finished = True
        self.maybe_toggle_state()

    def address_loading_finished(self):
        self.address_loading_finished = True
        self.maybe_toggle_state()

    def transactions_loading_finished(self):
        self.transactions_loading_finished = True
        self.maybe_toggle_state()

    def animation_finished(self):
        self.enter_animation.value = WalletActivityViewModel.EnterAnimationState.FINISHED

    def maybe_toggle_state(self):
        if not self.enter_animation.value:
            if self.do_animation and self.global_layout_finished:
                self.enter_animation.value = WalletActivityViewModel.EnterAnimationState.WAITING
        elif self.enter_animation.value == WalletActivityViewModel.EnterAnimationState.WAITING:
            if (self.balance_loading_finished and 
                    self.address_loading_finished and 
                    self.transactions_loading_finished):
                self.enter_animation.value = WalletActivityViewModel.EnterAnimationState.ANIMATING


class WalletEncryptedLiveData(AbstractWalletLiveData[bool]):
    def __init__(self, application: Application):
        super().__init__(application)

    @property
    def wallet(self) -> Wallet:
        return self._wallet

    @wallet.setter
    def wallet(self, value: Wallet):
        self._wallet = value

    def on_wallet_active(self, wallet: Wallet):
        self.load()

    def load(self):
        AsyncTask.execute(lambda: org.bitcoinj.core.Context.propagate(Constants.CONTEXT)
                          and post_value(self.wallet.is_encrypted()))


class WalletLegacyFallbackLiveData(AbstractWalletLiveData[bool]):
    def __init__(self, application: Application):
        super().__init__(application)

    @property
    def wallet(self) -> Wallet:
        return self._wallet

    @wallet.setter
    def wallet(self, value: Wallet):
        self._wallet = value

    def on_wallet_active(self, wallet: Wallet):
        self.load()

    def load(self):
        AsyncTask.execute(lambda: org.bitcoinj.core.Context.propagate(Constants.CONTEXT)
                          and post_value(self.wallet.get_active_key_chain().get_output_script_type() == Script.ScriptType.P2WPKH
                                         and self.wallet.get_active_key_chains()[0].get_output_script_type() != Script.ScriptType.P2WPKH))
