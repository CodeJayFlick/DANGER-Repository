class AddressBookActivity:
    def __init__(self):
        pass

    @staticmethod
    def start(context: Context) -> None:
        context.startActivity(Intent(context, AddressBookActivity))

    def onCreate(self, savedInstanceState: Bundle) -> None:
        super().onCreate(savedInstanceState)
        fragmentManager = self.getSupportFragmentManager()
        pager = findViewById(R.id.address_book_pager)
        pager_tabs = findViewById(R.id.address_book_pager_tabs)

        pager_tabs.addTabLabels(TAB_LABELS)

        two_panes = getResources().getBoolean(R.bool.address_book_two_panes)

        wallet_activity_view_model = ViewModelProvider(self).get(AbstractWalletActivityViewModel.class)
        wallet_activity_view_model.wallet.observe(self, lambda wallet: self.invalidateOptionsMenu())
        view_model = ViewModelProvider(self).get(AddressBookViewModel.class)
        view_model.page_to.observe(self, lambda position: pager.setCurrentItem(position, True))
        view_model.show_edit_address_book_entry_dialog.observe(self, lambda address: EditAddressBookEntryFragment.edit(fragmentManager, address))
        view_model.show_scan_own_address_dialog.observe(self, lambda _: DialogBuilder.dialog(AddressBookActivity.this, R.string.address_book_options_scan_title, R.string.address_book_options_scan_own_address).singleDismissButton(None).show())
        view_model.show_scan_invalid_dialog.observe(self, lambda _: DialogBuilder.dialog(AddressBookActivity.this, R.string.address_book_options_scan_title, R.string.address_book_options_scan_invalid).singleDismissButton(None).show())

        if two_panes:
            recyclerView = pager.getChildAt(0)
            recyclerView.setClipToPadding(False)
            recyclerView.getViewTreeObserver().addOnGlobalLayoutListener(lambda: 
                width = recyclerView.getWidth()
                recyclerView.setPadding(0, 0, width / 2, 0)
                pager.setCurrentItem(0))
            pager.setUserInputEnabled(False)
            pager_tabs.setMode(ViewPagerTabs.Mode.STATIC)

        else:
            pager.setPageTransformer(ZoomOutPageTransformer())
            pager.registerOnPageChangeCallback(pager_tabs.getPageChangeCallback())
            pager_tabs.setMode(ViewPagerTabs.Mode.DYNAMIC)

        pager.setOffscreenPageLimit(1)
        pager.setAdapter(AddressBookActivityPagerAdapter())

    def onActivityResult(self, requestCode: int, resultCode: int, intent: Intent) -> None:
        if requestCode == REQUEST_CODE_SCAN:
            if resultCode == Activity.RESULT_OK:
                input = intent.getStringExtra(ScanActivity.INTENT_EXTRA_RESULT)

                InputParser.StringInputParser(input).parse()

        else:
            super.onActivityResult(requestCode, resultCode, intent)

    def onCreateOptionsMenu(self, menu: Menu) -> bool:
        getMenuInflater().inflate(R.menu.address_book_activity_options, menu)
        pm = getPackageManager()
        menu.findItem(R.id.sending_addresses_options_scan).setVisible(pm.hasSystemFeature(PackageManager.FEATURE_CAMERA) or pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_FRONT))
        return super.onCreateOptionsMenu(menu)

    def onOptionsItemSelected(self, item: MenuItem) -> bool:
        itemId = item.getItemId()

        if itemId == R.id.sending_addresses_options_scan:
            ScanActivity.startForResult(self, REQUEST_CODE_SCAN)
            return True

        return super.onOptionsItemSelected(item)


class PagerAdapter(FragmentStateAdapter):
    def __init__(self):
        super().__init__()

    def getItemCount(self) -> int:
        return 2

    def createFragment(self, position: int) -> Fragment:
        if position == POSITION_WALLET_ADDRESSES:
            return WalletAddressesFragment()
        elif position == POSITION_SENDING_ADDRESSES:
            return SendingAddressesFragment()
        else:
            raise ValueError
