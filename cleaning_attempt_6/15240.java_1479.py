class DividerItemDecoration:
    ATTRS = [android.R.attr.listDivider]

    HORIZONTAL_LIST = 0
    VERTICAL_LIST = 1

    def __init__(self, context: 'Context', orientation: int) -> None:
        self.mDivider = context.obtainStyledAttributes(ATTRS).getDrawable(0)
        self.setOrientation(orientation)

    def setOrientation(self, orientation: int) -> None:
        if not (orientation == DividerItemDecoration.HORIZONTAL_LIST or
                orientation == DividerItemDecoration.VERTICAL_LIST):
            raise ValueError("Invalid orientation")
        self.mOrientation = orientation

    def onDraw(self, c: 'Canvas', parent: 'RecyclerView') -> None:
        if self.mOrientation == DividerItemDecoration.VERTICAL_LIST:
            self.drawVertical(c, parent)
        else:
            self.drawHorizontal(c, parent)

    def drawVertical(self, c: 'Canvas', parent: 'RecyclerView') -> None:
        left = parent.getPaddingLeft()
        right = parent.getWidth() - parent.getPaddingRight()
        childCount = parent.getChildCount()

        for i in range(childCount):
            child = parent.getChildAt(i)
            params = child.getLayoutParams()
            top = child.getBottom() + params.bottomMargin + round(child.getTranslationY())
            bottom = top + self.mDivider.getIntrinsicHeight()
            self.mDivider.setBounds(left, top, right, bottom)
            self.mDivider.draw(c)

    def drawHorizontal(self, c: 'Canvas', parent: 'RecyclerView') -> None:
        top = parent.getPaddingTop()
        bottom = parent.getHeight() - parent.getPaddingBottom()
        childCount = parent.getChildCount()

        for i in range(childCount):
            child = parent.getChildAt(i)
            params = child.getLayoutParams()
            left = child.getRight() + params.rightMargin + round(child.getTranslationX())
            right = left + self.mDivider.getIntrinsicWidth()
            self.mDivider.setBounds(left, top, right, bottom)
            self.mDivider.draw(c)

    def getItemOffsets(self, outRect: 'Rect', itemPosition: int, parent: 'RecyclerView') -> None:
        if self.mOrientation == DividerItemDecoration.VERTICAL_LIST:
            outRect.set(0, 0, 0, self.mDivider.getIntrinsicHeight())
        else:
            outRect.set(0, 0, self.mDivider.getIntrinsicWidth(), 0)
