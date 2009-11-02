"""Simple script which runs VNS and then periodically checks to see if VNS
seems to still be alive.  If not, it restarts VNS."""

from datetime import datetime
from subprocess import Popen
from time import sleep, time

import settings
from web.vnswww import models as db

logfile = open('vns_monitor.log', 'w')
def log(s):
    msg = 'VNS Monitor: %s: %s' % (datetime.now(), s)
    print msg
    logfile.write(msg + '\n')
    logfile.flush()

def stop_vns(vns):
    vns.terminate()
    sleep(3.0)
    vns.kill()

try:
    log('starting VNS')
    arg = ["/usr/bin/env", "python", "VNS.py"]
    vns = Popen(arg)
    while True:
        sleep(60.0)

        try:
            t = int(db.SystemInfo.objects.get(name='last_alive_time').value)
            diff = time() - t
        except db.SystemInfo.DoesNotExist:
            diff = 9999999

        if diff > 120:
            log('VNS has not checked in for %dsec: stopping VNS' % int(diff))
            stop_vns(vns)
            log('starting a new VNS')
            vns = Popen(arg)
            log('new VNS pid = %d' % vns.pid)
except KeyboardInterrupt:
    log('shutting down VNS')
    stop_vns(vns)
    logfile.close()
