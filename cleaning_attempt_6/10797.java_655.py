class VisualGraphPickingGraphMousePlugin(V):
    def __init__(self):
        super().__init__()

    def checkModifiers(self, e):
        if e.getModifiersEx() == self.addToSelectionModifiers:
            return True
        else:
            return e.getModifiersEx() == self.modifiers

    def mousePressed(self, e):
        if not self.checkModifiers(e):
            return
        super().mousePressed(e)

    def mouseDragged(self, e):
        if self.locked:
            return

        viewer = self.getGraphViewer(e)
        if self.vertex is not None:
            self.dragVertices(e, viewer)
        else:
            self.increaseDragRectangle(e)

        viewer.repaint()

    def increaseDragRectangle(self, e):
        out = e.getPoint()
        theModifiers = e.getModifiersEx()
        if theModifiers == self.addToSelectionModifiers or theModifiers == self.modifiers:
            if self.down is not None:
                rect.setFrameFromDiagonal(self.down, out)

    def dragVertices(self, e, viewer):
        p = e.getPoint()
        context = viewer.getRenderContext()
        xformer = context.getMultiLayerTransformer()
        layoutDown = xformer.inverseTransform(self.down)
        layoutPoint = xformer.inverseTransform(p)
        dx = layoutPoint.getX() - layoutDown.getX()
        dy = layoutPoint.getY() - layoutDown.getY()

        for v in self.ps.getPicked():
            vertexPoint = layout.apply(v)
            vertexPoint.setLocation(vertexPoint.getX() + dx, vertexPoint.getY() + dy)
            layout.setLocation(v, vertexPoint)

            self.updatedArticulatedEdges(viewer, v)

        self.down = p
        e.consume()

    def updatedArticulatedEdges(self, viewer, v):
        layout = viewer.getGraphLayout()
        graph = layout.getGraph()

        edges = graph.getIncidentEdges(v)
        updater = self.getViewUpdater(viewer)
        updater.updateEdgeShapes(edges)

    def mouseMoved(self, e):
        if self.isOverVertex(e):
            self.installCursor(cursor, e)
            e.consume()

    def isOverVertex(self, e):
        viewer = self.getViewer(e)
        return GraphViewerUtils.getVertexFromPointInViewSpace(viewer, e.getPoint()) != None

    @staticmethod
    def installCursor(newCursor, e):
        viewer = (VisualizationViewer(V, E)) e.getSource()
        viewer.setCursor(newCursor)

    def mouseReleased(self, e):
        if not self.isDragging() and self.vertex is None and self.edge is None:
            maybeClearPickedState(e)
        super().mouseReleased(e)

    @staticmethod
    def maybeClearPickedState(event):
        vv = (VisualizationViewer(V, E)) event.getSource()
        pickedVertexState = vv.getPickedVertexState()
        pickedEdgeState = vv.getPickedEdgeState()

        if pickedEdgeState is None or pickedVertexState is None:
            return

        pickSupport = vv.getPickSupport()
        layout = vv.getGraphLayout()

        mousePoint = event.getPoint()
        v = pickSupport.getVertex(layout, mousePoint.getX(), mousePoint.getY())
        e = pickSupport.getEdge(layout, mousePoint.getX(), mousePoint.getY())

        if v is not None or e is not None:
            return

        pickedEdgeState.clear()
        pickedVertexState.clear()

    def getGraphViewer(self, e):
        # implement this method
        pass

    def getViewUpdater(self, viewer):
        # implement this method
        pass

    @staticmethod
    def installCursor(newCursor, event):
        # implement this method
        pass
