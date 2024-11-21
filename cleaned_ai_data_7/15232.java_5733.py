import logging
from android import Activity, Dialog, Bundle, Context, Window
from androidx.fragment.app import DialogFragment, FragmentManager
from PIL import Image as Bitmap  # Assuming you have Pillow installed
from io import BytesIO

class BitmapFragment(DialogFragment):
    FRAGMENT_TAG = type.__name__
    KEY_BITMAP = "bitmap"

    @classmethod
    def show(cls, fm: FragmentManager, bitmap: Bitmap) -> None:
        instance(bitmap).show(fm, cls.FRAGMENT_TAG)

    @classmethod
    def instance(cls, bitmap: Bitmap) -> 'BitmapFragment':
        fragment = BitmapFragment()
        args = Bundle()
        args.putParcelable(BitmapFragment.KEY_BITMAP, bitmap)
        fragment.setArguments(args)
        return fragment

    activity: Activity = None

    log = logging.getLogger(type.__name__)

    def on_attach(self, context: Context) -> None:
        super().onAttach(context)
        self.activity = (context)

    def on_create(self, savedInstanceState: Bundle) -> None:
        super().onCreate(savedInstanceState)
        self.log.info("opening dialog {}", type.__name__)

    def on_create_dialog(self, savedInstanceState: Bundle) -> Dialog:
        args = self.getArguments()
        bitmap = BitmapDrawable(Bitmap.frombytes('RGBA', (0, 0), BytesIO(bitmap)), get_resources())
        bitmap.set_filter_bitmap(False)

        dialog = Dialog(self.activity)
        dialog.request_window_feature(Window.FEATURE_NO_TITLE)
        dialog.set_content_view(get_layout(R.layout.bitmap_dialog))
        dialog.set_canceled_on_touch_outside(True)

        imageview = dialog.findViewById(R.id.bitmap_dialog_image)
        imageview.setImageDrawable(bitmap)
        imageview.setOnClickListener(lambda v: self.dismiss_allowing_state_loss())

        return dialog
