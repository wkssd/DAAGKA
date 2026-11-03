#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
build = here.parents[3] / 'build'
output = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/iot-ns3-gka')
if not output.parent.is_dir() or not (build / 'libns3.25-core-debug.so').is_file():
    sys.exit('Missing output parent or existing NS3.25 libraries')
subprocess.check_call([
    'g++', '-std=c++11', '-O2', '-Wall', '-Wextra', '-Werror',
    '-isystem', str(build), str(here / 'ns3-gka.cc'), '-L' + str(build),
    '-Wl,-rpath,' + str(build), '-lns3.25-wifi-debug', '-lns3.25-mobility-debug',
    '-lns3.25-internet-debug', '-lns3.25-network-debug', '-lns3.25-core-debug',
    '-lns3.25-propagation-debug', '-lns3.25-olsr-debug', '-lcrypto', '-o', str(output)])
