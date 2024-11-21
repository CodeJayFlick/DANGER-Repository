import threading

class GTreeNode:
    def __init__(self):
        pass

class GTreeTask:
    def run(self, monitor):
        max = 100
        monitorWrapper = UnknownProgressWrappingTaskMonitor(monitor, max)
        monitorWrapper.initialize(max)
        monitorWrapper.setMessage("Collapsing nodes...")
        try:
            self.collapseNode(root, monitorWrapper)
        except CancelledException as e:
            # Not everything expanded which is ok
            pass

    def collapseNode(self, node, monitor):
        if node.isLeaf():
            return
        monitor.checkCanceled()
        allChildren = node.getChildren()
        if len(allChildren) == 0:
            return
        treePath = node.getTreePath()
        if jTree.isExpanded(treePath):
            self.collapsePath(treePath, monitor)
        for child in allChildren:
            monitor.checkCanceled()
            self.collapseNode(child, monitor)
        monitor.incrementProgress(1)

    def collapsePath(self, treePath, monitor):
        threading.Thread(target=lambda: self._collapsePathOnSwingThread(monitor)).start()

    def _collapsePathOnSwingTree(self, monitor):
        if monitor.isCancelled():
            return  # we can be cancelled while waiting for Swing to run us
        jTree.collapsePath(treePath)

class UnknownProgressWrappingTaskMonitor:
    def __init__(self, monitor, max):
        self.monitor = monitor
        self.max = max

    def initialize(self, max):
        pass

    def setMessage(self, message):
        pass

    def checkCanceled(self):
        pass

    def incrementProgress(self, step):
        pass

class CancelledException(Exception):
    pass
