Here is your Java code translated into Python:

```Python
import unittest
from typing import Tuple

class PopupWindowPlacerTest(unittest.TestCase):

    def setUp(self):
        self.screen = Rectangle(0, 0, 2000, 1000)
        self.center = Rectangle(200, 200, 1600, 600)

    def testLeftmostTop(self):
        placer = PopupWindowPlacerBuilder().topEdge(Location.LEFT).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x - Rectangle(100, 100, 50, 50).width, self.center.y - Rectangle(100, 100, 50, 50).height)
        self.assertTrue(self.screen.contains(placement))
        self.assertEqual(Rectangle(expected, Rectangle(100, 100, 50, 50)), placement)

    def testUpperLeft(self):
        placer = PopupWindowPlacerBuilder().leftEdge(Location.TOP).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x - Rectangle(100, 100, 50, 50).width, self.center.y - Rectangle(100, 100, 50, 50).height)
        self.assertTrue(self.screen.contains(placement))
        self.assertEqual(Rectangle(expected, Rectangle(100, 100, 50, 50)), placement)

    def testLeftmostBottom(self):
        placer = PopupWindowPlacerBuilder().bottomEdge(Location.LEFT).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x - Rectangle(100, 100, 50, 50).width, self.center.y + self.center.height)
        self.assertTrue(self.screen.contains(placement))
        self.assertEqual(Rectangle(expected, Rectangle(100, 100, 50, 50)), placement)

    def testLowerLeft(self):
        placer = PopupWindowPlacerBuilder().leftEdge(Location.BOTTOM).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x - Rectangle(100, 100, 50, 50).width, self.center.y + self.center.height)
        self.assertTrue(self.screen.contains(placement))
        self.assertEqual(Rectangle(expected, Rectangle(100, 100, 50, 50)), placement)

    def testRightmostTop(self):
        placer = PopupWindowPlacerBuilder().topEdge(Location.RIGHT).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x + self.center.width - Rectangle(100, 100, 50, 50).width, self.center.y - Rectangle(100, 100, 50, 50).height)
        self.assertTrue(self.screen.contains(placement))
        self.assertEqual(Rectangle(expected, Rectangle(100, 100, 50, 50)), placement)

    def testUpperRight(self):
        placer = PopupWindowPlacerBuilder().rightEdge(Location.TOP).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x + self.center.width - Rectangle(100, 100, 50, 50).width, self.center.y - Rectangle(100, 100, 50, 50).height)
        self.assertTrue(self.screen.contains(placement))
        self.assertEqual(Rectangle(expected, Rectangle(100, 100, 50, 50)), placement)

    def testRightmostBottom(self):
        placer = PopupWindowPlacerBuilder().bottomEdge(Location.RIGHT).build()
        placement = placer.get_placement(Rectangle(100, 100, 50, 50), self.center, self.screen)
        expected = Point(self.center.x + self.center.width - Rectangle(100, 100, 50, 50), self.assertEqual(Rectangle(100, 100, 50, 50), placement=placement)

    def testLeftmostTopNeedsShiftLeft()