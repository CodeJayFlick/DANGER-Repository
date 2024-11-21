import logging
from androidhelper import *

class ExtendedPublicKeyFragment(DialogFragment):
    FRAGMENT_TAG = type.__name__
    KEY_EXTENDED_PUBLIC_KEY = "extended_public_key"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.activity = None

    @classmethod
    def show(cls, fm, base58):
        instance(base58).show(fm, cls.FRAGMENT_TAG)

    @classmethod
    def instance(cls, base58):
        fragment = ExtendedPublicKeyFragment()
        args = Bundle()
        args.putString(KEY_EXTENDED_PUBLIC_KEY, str(base58))
        fragment.setArguments(args)
        return fragment

    def onAttach(self, activity):
        super().onAttach(activity)
        self.activity = activity

    def onCreateDialog(self, savedInstanceState):
        base58 = getArguments().getString(ExtendedPublicKeyFragment.KEY_EXTENDED_PUBLIC_KEY)

        view = LayoutInflater.from(self.activity).inflate(R.layout.extended_public_key_dialog, None)

        bitmap = BitmapDrawable(getResources(), Qr.bitmap(str(base58)))
        bitmap.setFilterBitmap(False)
        imageView = view.findViewById(R.id.extended_public_key_dialog_image)
        imageView.setImageDrawable(bitmap)

        dialog = DialogBuilder.custom(self.activity, 0, view)
        dialog.setNegativeButton(R.string.button_dismiss, lambda d, which: self.dismissAllowingStateLoss())
        dialog.setPositiveButton(R.string.button_share, lambda d, which:
            ShareCompat.IntentBuilder.from(self.activity).setType("text/plain").setText(str(base58)).setSubject(getString(R.string.extended_public_key_fragment_title)).setChooserTitle(R.string.extended_public_key_fragment_share).startChooser()
        )

        return dialog.show()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
