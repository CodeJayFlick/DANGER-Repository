Here is the translation of the Java code into Python:

```Python
class GlyphContext:
    def __init__(self, scale, width, height):
        self.mScale = scale
        self.mWidth = width
        self.mHeight = height
        
        self.mXsContext = []
        self.mYsContext = []
        self.mDXsContext = []
        self.mDYsContext = []
        self.mRsContext = []

        self.mFontContext = [None]
        self.mXIndices = [0]
        self.mYIndices = [0]
        self.mDXIndices = [0]
        self.mDYIndices = [0]
        self.mRIndices = [0]

    def pushNodeAndFont(self, node, font):
        parent_font = self.getTopOrParentFont(node)
        self.mTop += 1

        if font is None:
            self.mFontContext.append(parent_font)
            return
        data = FontData(font, parent_font, self.mScale)
        self.mFontSize = data.font_size
        self.mFontContext.append(data)
        self.topFont = data

    def pushContext(self, node, font):
        self.pushNodeAndFont(node, font)
        self.pushIndices()

    def reset(self):
        self.mXsIndex = 0
        self.mYsIndex = 0
        self.mDXsIndex = 0
        self.mDYsIndex = 0
        self.mRsIndex = 0

        self.mXIndex = -1
        self.mYIndex = -1
        self.mDXIndex = -1
        self.mDYIndex = -1
        self.mRIndex = -1

    def popContext(self):
        if len(self.mFontContext) > 1:
            self.mFontContext.pop()
            self.mXIndices.pop()
            self.mYIndices.pop()
            self.mDXIndices.pop()
            self.mDYIndices.pop()
            self.mRIndices.pop()

            self.mTop -= 1

    def getFontSize(self):
        return self.mFontSize

    def next_x(self, advance):
        if len(self.mXs) > self.mXIndex + 1:
            mDX = 0
            self.mXIndex += 1
            string = self.mXs[self.mXIndex]
            self.mX = PropHelper.from_relative(string, self.mWidth, 0, self.mScale, self.mFontSize)
        else:
            return None

        self.mX += advance
        return self.mX

    def next_y(self):
        if len(self.mYs) > self.mYIndex + 1:
            mDY = 0
            self.mYIndex += 1
            string = self.mYs[self.mYIndex]
            self.mY = PropHelper.from_relative(string, self.mHeight, 0, self.mScale, self.mFontSize)
        else:
            return None

        return self.mY

    def next_delta_x(self):
        if len(self.mDXs) > self.mDXIndex + 1:
            mDXIndex += 1
            string = self.mDXs[self.mDXIndex]
            val = PropHelper.from_relative(string, self.mWidth, 0, self.mScale, self.mFontSize)
            self.mDX += val
        else:
            return None

        return self.mDX

    def next_delta_y(self):
        if len(self.mDYs) > self.mDYIndex + 1:
            mDYIndex += 1
            string = self.mDYs[self.mDYIndex]
            val = PropHelper.from_relative(string, self.mHeight, 0, self.mScale, self.mFontSize)
            self.mDY += val
        else:
            return None

        return self.mDY

    def next_rotation(self):
        if len(self.mRs) > self.mRIndex + 1:
            mRIndex = min(mRIndex + 1, len(self.mRs) - 1)

        return self.mRs[self.mRIndex]

    def get_width(self):
        return self.mWidth

    def get_height(self):
        return self.mHeight
```

Please note that this is a direct translation of the Java code into Python. The logic and functionality remain the same, but some minor adjustments might be necessary to make it work perfectly in your specific use case.