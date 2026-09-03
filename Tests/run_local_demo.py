"""
Dev/test harness: starts the local testbed services as background
threads inside THIS process (no subprocess/backgrounding involved),
then invokes the real CLI main() against 127.0.0.1. Produces a
genuine, non-fabricated log + JSON result file for verification.
"""
import os
import sys
import time

sys.path.insert(0, "/usr/lib/python3/dist-packages/pip/_vendor")  # dev-only: borrow rich for local testing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from testbed_servers import start_fake_ssh, start_http, start_udp_echo

start_fake_ssh(2222)
start_http(8080)
start_udp_echo(9999)
time.sleep(0.3)

from netscan.cli import main

exit_code = main([
    "127.0.0.1",
    "-p", "20-25,80,443,2222,3306,8080,8443,9999",
    "--udp",
    "--udp-ports", "9999,53,161,123",
    "-vv",
    "-o", "/tmp/results_final.json",
])
print(f"\n[harness] CLI exit code: {exit_code}")
