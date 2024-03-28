"""Main module of talitarp/contention_block Kytos Network Application."""

from kytos.core import KytosNApp, log, rest
from kytos.core import KytosEvent
from kytos.core.helpers import listen_to
from kytos.core.rest_api import (HTTPException, JSONResponse, Request,
                                 get_json_or_400)  
from napps.amlight.sdntrace_cp.utils import (convert_entries,
                                             convert_list_entries,
                                             find_endpoint, get_stored_flows,
                                             match_field_dl_vlan,
                                             match_field_ip, prepare_json)

class Main(KytosNApp):
    """Main class of talitarp/contention_block NApp.This class is the entry point for this napp."""  
    
     """ Handle the LOCK contention event"""

    def setup(self):
    """Replace the '__init__' method for the KytosNApp subclass.

        The setup method is automatically called by the controller when your
        application is loaded.
        
        log.info("Starting Kytos contention_block NApp!")

        It is not necessary in this NApp. 
    """

    def execute(self):
    """This method is executed right after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.
        
        It is not necessary in this NApp. 
    """

    def shutdown(self):
    """This method is executed when your napp is unloaded.

        If you have some cleanup procedure, insert it here:
            log.info('SHUTDOWN contention_block')
            
        It is not necessary in this NApp. 
     """
        
     @rest('/v1/contention_block/', methods=['POST'])
     def contention_block(self, request: Request) -> JSONResponse:
         data=get_json_or_400(request, self.controller.loop) #access user request
         entries = convert_entries(data)
         if not entries:
             raise HTTPException(400, "Empty entries")
                
     """A PARTIR DAQUI:
     Nesse momento passei a ter acesso aos parametros da requisição do usuario.
     Missão: processar a requisição do user para entender que solicitação de bloqueio ele quer fazer.
     Recebo do user alguns argumentos. O user me diz qual: 1- o switch , 2- a porta e 3 - quais sao os criterios de match do pacote que quer usar para bloquear o trafego.
     match: ip origem, porta tcp, porta udp...

      Regra de bloqueio:
      Não vou fazer mais o self.add_flow(dp, 65534, match, actions)
      Vou ter que fazer uma requisção "api HTTP rest" para a NApp da Flow Manager informando os matches,
      informando o fluxo que quero criar, os matches, a action é vazia, qual o switch que quero bloquear...
     """
       actions = [] #significa que tem o block pois action esta vazia.

         for sw in self.net.nodes():
             dp = self.net.node[sw]['conn']
             for port in self.get_access_ports(sw):
                 for vlan in self.eline_map:
                     # the dl_vlan match is a workaround because flowvisor seems to bug when using
                     # dl_type=0x0800
                     match = {'in_port': port, 'dl_type': 0x0800, 'dl_vlan': vlan, 'nw_src': request}
                     self.add_flow(dp, 65534, match, actions)
         return (True, 'Success')

    """MENSAGENS DE SUCESSO OU ERRO:
        return JSONResponse ("block ok")
        raise HTTPException (400, "Invalid request")
    """
