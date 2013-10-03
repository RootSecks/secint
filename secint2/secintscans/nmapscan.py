#!/usr/bin/python

import nmap

class NmapScan():
    def __init__(self, options):
        pipe = subprocess.Popen(["./nmapdb.pl", options], stdout=subprocess.PIPE)
        result = pipe.stdout.read()
        return result