class ListRendererMouseEventForwarder:
    def mouseMoved(self, event):
        self.redispatchEvent(event)

    def mouseEntered(self, event):
        self.redisdispatchEvent(event)

    def mouseExited(self, event):
        self.redisdispatchEvent(event)

    def mousePressed(self, event):
        self.redisdispatchEvent(event)

    def mouseReleased(self, event):
        self.redisdispatchEvent(event)

    def mouseClicked(self, event):
        self.redisdispatchEvent(event)

    def redisdispatchEvent(self, event):
        list = event.getSource()
        index = list.locationToIndex(event.getPoint())
        cellBounds = list.getCellBounds(index, index)
        
        if cellBounds is None:
            return
        
        model = list.getModel()
        state = model.getElementAt(index)
        
        renderer = list.getCellRenderer()
        rendererComponent = renderer.getListCellRendererComponent(list, state, index, True, True)
        rendererComponent.setBounds(cellBounds)

        p = event.getPoint()
        p.translate(-cellBounds.x, -cellBounds.y)

        newEvent = MouseEvent(rendererComponent, event.getId(), event.getWhen(), event.getModifiers(),
                              p.x, p.y, event.getXOnScreen(), event.getYOnScreen(), event.getClickCount(),
                              event.isPopupTrigger(), event.getButton())
        
        rendererComponent.dispatchEvent(newEvent)
        list.repaint()
