import base64
from io import ByteArrayOutputStream
from PIL import Image
import math

class SvgView:
    def __init__(self):
        self.mRendered = False
        self.toDataUrlTask = None
        self.mBitmap = None
        self.mCanvas = None
        self.mScale = 1.0
        self.mMinX = 0.0
        self.mMinY = 0.0
        self.mVbWidth = 0.0
        self.mVbHeight = 0.0
        self.mbbWidth = SVGLength(0, 0)
        self.mbbHeight = SVGLength(0, 0)
        self.mAlign = None
        self.mMeetOrSlice = 0

    def setId(self, id):
        super().setId(id)

    def invalidate(self):
        if not self.mRendered:
            return
        parent = getParent()
        if isinstance(parent, VirtualView) and not mRendered:
            ((VirtualView)parent).getSvgView().invalidate()
            return
        if self.mBitmap is not None:
            self.mBitmap.recycle()
        self.mBitmap = None

    def onDraw(self, canvas):
        if getParent() is not None and isinstance(getParent(), VirtualView):
            return
        super.onDraw(canvas)
        if self.mBitmap is None:
            self.mBitmap = drawOutput()
        if self.mBitmap is not None:
            canvas.drawBitmap(self.mBitmap, 0, 0, None)
            if toDataUrlTask is not None:
                toDataUrlTask.run()
                toDataUrlTask = None

    def onSizeChanged(self, w, h, oldw, oldh):
        super.onSizeChanged(w, h, oldw, oldh)
        self.invalidate()

    def reactTagForTouch(self, touchX, touchY):
        return hitTest(touchX, touchY)

    # Other methods...

class SVGLength:
    def __init__(self, width, height):
        self.width = width
        self.height = height

    @staticmethod
    def from(width, height, scale=1.0):
        return SVGLength(width * scale, height * scale)

class VirtualView:
    # Other methods...

def drawOutput(self):
    if not mRendered:
        return None
    w, h = self.getWidth(), self.getHeight()
    invalid = math.isnan(w) or math.isnan(h) or w < 1.0 or h < 1.0 or (math.log10(w) + math.log10(h)) > 42
    if invalid:
        return None
    bitmap = Image.new('RGBA', int(w), int(h))
    drawChildren(bitmap)
    return bitmap

def getCanvasBounds(self):
    # Return the bounds of the canvas...
    pass

def drawChildren(self, canvas):
    mRendered = True
    mViewBoxMatrix = Matrix()
    if self.mAlign is not None:
        vbRect = getViewBox()
        w, h = canvas.size
        nested = getParent() is not None and isinstance(getParent(), VirtualView)
        if nested:
            w *= PropHelper.fromRelative(self.mbbWidth.width, 0.0, mScale, 12)
            h *= PropHelper.fromRelative(self.mbbHeight.height, 0.0, mScale, 12)
        eRect = RectF(0, 0, w, h)
        if nested:
            canvas.clip_rect(eRect)
        mViewBoxMatrix = ViewBox.getTransform(vbRect, eRect, self.mAlign, self.mMeetOrSlice)
        mInvertible = mViewBoxMatrix.invert(mInvViewBoxMatrix)
        canvas.concat(mViewBoxMatrix)

    for i in range(self.getChildCount()):
        node = self.getChildAt(i)
        if isinstance(node, VirtualView):
            ((VirtualView)node).saveDefinition()

    for i in range(self.getChildCount()):
        lNode = self.getChildAt(i)
        if isinstance(lNode, VirtualView):
            node = (VirtualView)lNode
            count = node.saveAndSetupCanvas(canvas, mViewBoxMatrix)
            node.render(canvas, paint, 1.0)
            node.restoreCanvas(canvas, count)

def getViewBox(self):
    return RectF(self.mMinX * self.mScale, self.mMinY * self.mScale,
                 (self.mMinX + self.mVbWidth) * self.mScale,
                 (self.mMinY + self.mVbHeight) * self.mScale)
