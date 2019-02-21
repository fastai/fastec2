#!/usr/bin/env python
from fastec2 import *

e = EC2('Oregon')
print('-- instances --')
e.instances()
print('-- volumes --')
e.print_resources('volumes')
print('-- snapshots --')
e.print_resources('snapshots', owned=True)
print('-- amis --')
e.amis()

