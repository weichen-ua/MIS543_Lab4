'''
Udacity: ud436/sdn-firewall
Professor: Nick Feamster
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr, IPAddr
from collections import namedtuple
import os
from csv import DictReader


log = core.getLogger()
policyFile = "/home/mininet/MIS307/Lab4/firewall-policies.csv" 

# Add your global variables here ...

# Note: Policy is data structure which contains a single
# source-destination flow to be blocked on the controller.
Policy = namedtuple('Policy', ('ip_src', 'ip_dst'))


class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def read_policies (self, file):
        with open(file, 'r') as f:
            reader = DictReader(f, delimiter = ",")
            policies = {}
            for row in reader:
                policies[row['id']] = Policy(IPAddr(row['ip_src']), IPAddr(row['ip_dst']))
        return policies

    def _handle_ConnectionUp (self, event):
        policies = self.read_policies(policyFile)
        for policy in policies.itervalues():
            # use ofp_flow_mod to modify the flow table
            msg = of.ofp_flow_mod()
            msg.priority = 20
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE)) # output to nowhere

            # use openflow match to add the firewall rules
            match = of.ofp_match()
            match.dl_type = 0x800

            # policy to block from ip_src to ip_dst
            match.nw_src = policy.ip_src
            match.nw_dst = policy.ip_dst
            msg.match = match
            event.connection.send(msg)

            # debug
            log.info("Installing firewall rule for src=%s, dst=%s" % (policy.ip_src, policy.ip_dst))
            log.debug(msg)


        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))


def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
