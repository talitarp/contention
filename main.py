"""Main module of talitarp/kytosContainment Kytos Network Application."""

from flask import jsonify, request
from kytos.core import KytosNApp, log, rest
from kytos.core import KytosEvent
from kytos.core.helpers import listen_to

class Main(KytosNApp):
    """Main class of talitarp/kytosContainment NApp.This class is the entry point for this napp."""  
    
     """ Handle the LOCK contention event"""

     @rest('/v1/contention_block/', methods=['POST'])
     def contention_block(self, request):
         data=get_json_or_400(request,self.controller.loop)
            print "==> contention_block ipaddr=%s in all switches" % (ipaddr)
            actions = []
            for sw in self.net.nodes():
                dp = self.net.node[sw]['conn']
                for port in self.get_access_ports(sw):
                    for vlan in self.eline_map:
                        # the dl_vlan match is a workaround because flowvisor seems to bug when using
                        # dl_type=0x0800
                        match = {'in_port': port, 'dl_type': 0x0800, 'dl_vlan': vlan, 'nw_src': ipaddr}
                        self.add_flow(dp, 65534, match, actions)
            return (True, 'Success')
