from __future__ import absolute_import

__author__ = 'Your Name'
__version__ = '1.0'

import pkg_resources

try:
    _distributions = {'ai.djl.training.loss': str(pkg_resources.get_distribution('ai.djl.training.loss'))}
except pkg_resources.DistributionNotFound:
    pass
