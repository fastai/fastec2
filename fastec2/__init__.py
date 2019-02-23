#!/usr/bin/env python

import fire,sys
from .ec2 import *
from .spot import *

def main():
    if len(sys.argv)>=2 and sys.argv[1]=='i': interact(*sys.argv[2:])
    else: fire.Fire(EC2)

if __name__ == '__main__': main()

