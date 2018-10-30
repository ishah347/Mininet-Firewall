#!/usr/bin/python
# coding: utf-8
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
import csv


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    # Credits to http://www.anshumanc.ml/networks/2017/09/19/firewall/ for inspiration for this problem.
    def _handle_ConnectionUp (self, event):    
        # Have program read and take note of the firewall policies.
        with open(policyFile) as csvfile:
            policy_reader = csv.reader(csvfile)
            next(policy_reader)
            # Block flow between IP addresses if firewall policy requires it.
            for row in policy_reader:
                stop = of.ofp_match()
                stop.dl_src = EthAddr(row[1])
                stop.dl_dst = EthAddr(row[2])
                flow_mod = of.ofp_flow_mod()
                flow_mod.match = stop
                event.connection.send(flow_mod)

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
