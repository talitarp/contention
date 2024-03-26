"""Main module of talitarp/contention_block Kytos Network Application."""

from kytos.core import KytosNApp, log, rest
from kytos.core import KytosEvent
from kytos.core.helpers import listen_to
from kytos.core.rest_api import (HTTPException, JSONResponse, Request,
                                 get_json_or_400)  

class Main(KytosNApp):
    """Main class of talitarp/contention_block NApp.This class is the entry point for this napp."""  
    
     """ Handle the LOCK contention event"""

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.

        """
        log.info("Starting Kytos SDNTrace CP App!")

    def execute(self):
        """This method is executed right after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        """

    def shutdown(self):
        """This method is executed when your napp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        
     @rest('/v1/contention_block/', methods=['POST'])
     def contention_block(self, request: Request) -> JSONResponse:
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
