"""Main module of talitarp/contention Kytos Network Application."""

import requests
import json
from uuid import uuid4
from kytos.core import KytosNApp, log, rest
from kytos.core import KytosEvent
from kytos.core.helpers import listen_to
from kytos.core.rest_api import (HTTPException, JSONResponse, Request,
                                 get_json_or_400)
from .settings import (
    COOKIE_PREFIX,
)

class Main(KytosNApp):
    """Main class of talitarp/contention NApp.This class is the entry point for this napp."""

    def setup(self):
        """Replace the '__init__' method for the KytosNApp subclass.

            The setup method is automatically called by the controller when your
            application is loaded.

            log.info("Starting Kytos contention NApp!")
        """
        log.info("Starting Kytos contention NApp!")
        self.stored_blocks = {"blocks": {}}
        """
        stored_blocks = {"blocks": {
            "block_id" : {
            "switch": "...",
            "interface": "...",
            "match": {in_port, dl_vlan, nw_src, nw_dst, nw_proto...},
            }
        }}
        """
        self.list_blocks = []

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
      
    def validate_input(self, data, action):
        if action == 'POST' or action == 'GET':
            # TODO: validate all user inputs
            mandatory_fields = ["switch", "interface", "match"]
            # check switch
            switch_id = data.get("switch")
            if not switch_id or switch_id not in self.controller.switches:
                return False, f"Invalid switch: {switch_id}"
            switch = self.controller.switches[switch_id]

            # check interface (port_no 1)
            try:
                port_no = data.get("interface", "")
                port_no = int(port_no)
            except:
                return False, f"Invalid interface: {port_no}"
            if port_no not in switch.interfaces:
                return False, f"Unknown interface: {port_no}"
            interface = switch.interfaces[port_no]

            # check matching fields
            match = data.get("match")
            if not match:
                return False, f"Invalid match: {match}"
            if "vlan" not in match:
               return False, "Missing mandatory field vlan on match"

            expected_fields = ["ipv4_src", "ipv4_dst", "ipv6_src", "ipv6_dst", "ip_proto", "sport", "dport", "vlan", "tcp_src", "tcp_dst", "udp_src", "udp_dst"]
            for key in match:
                if key not in expected_fields:
                    return False, f"Unexpected input match field: {key}"
			
            #check matching fields: TCP or UDP (Mandatory IPV4 or IPV6 specification)
            if "tcp_src" or "tcp_dst" or "udp_src" or "udp_dst" in match:
                if "ipv4_src" in match:
		elif "ipv4_dst" in match:
		elif "ipv6_src" in match:
		elif "ipv6_dst" in match:
		else:
                    return False, f"Missing mandatory ipv4 or ipv6 on match"
			
			
        if action == 'DELETE':
            if "block_id" not in data:
                return False, "Missing mandatory field block_id on data"
            
        return True, "success"
      
    def get_payload(self, data, block_id, action):
        #Call flow_manager's REST API to create the flow
        #payload = {"flows": [{"priority": 30000, "hard_timeout": xxx, "cookie": 0xee00000000000001, "match": {"in_port": xxx, "dl_vlan": xxx, "nw_src": xxx, "nw_dst": xxx, "nw_proto": xxx, "ipv6_src"=xxx, "ipv6_dst"=xxx, "tcp_src"=xxx, "tcp_dst"=xxx, "udp_src"=xxx, "udp_dst"=xxx}, "actions": []}]}

        cookie = COOKIE_PREFIX + block_id
        cookie = int(cookie, 16)
        if action == 'POST' or action == 'GET':
            payload = {"flows": [{"priority": 30000, "cookie": cookie, "match": {"in_port": int(data["interface"]), "dl_vlan": data["match"]["vlan"]}, "actions": []}]}
        
            if "ipv4_src" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x800
                payload["flows"][0]["match"]["nw_src"] = data["match"]["ipv4_src"]
            if "ipv4_dst" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x800
                payload["flows"][0]["match"]["nw_dst"] = data["match"]["ipv4_dst"]
            if "ipv6_src" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x86dd
                payload["flows"][0]["match"]["ipv6_src"] = data["match"]["ipv6_src"]
            if "ipv6_dst" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x86dd
                payload["flows"][0]["match"]["ipv6_dst"] = data["match"]["ipv6_dst"]
            if "ip_proto" in data["match"]:
                payload["flows"][0]["match"]["nw_proto"] = data["match"]["ip_proto"]
            if "tcp_src" in data["match"]:
                payload["flows"][0]["match"]["nw_proto"] = 6 
                payload["flows"][0]["match"]["tp_src"] = data["match"]["tcp_src"]
            if "tcp_dst" in data["match"]:
                payload["flows"][0]["match"]["nw_proto"] = 6
                payload["flows"][0]["match"]["tp_dst"] = data["match"]["tcp_dst"]
            if "udp_src" in data["match"]:
                payload["flows"][0]["match"]["nw_proto"] = 17
                payload["flows"][0]["match"]["udp_src"] = data["match"]["udp_src"]
            if "udp_dst" in data["match"]:
                payload["flows"][0]["match"]["nw_proto"] = 17
                payload["flows"][0]["match"]["udp_dst"] = data["match"]["udp_dst"]


        if action == 'DELETE': 
            block_id = data.get("block_id")
            # payload = {"flows": [{"priority": 30000, "cookie": 0xee00000000000001, "cookie_mask": 0xffffffffffffffff, "match": {"in_port": int(data["interface"]), "dl_vlan": data["match"]["vlan"]}, "actions": []}]}
            payload = {"flows": [{"priority": 30000, "cookie": cookie, "cookie_mask": 0xffffffffffffffff, "match": {"in_port": int(self.stored_blocks["blocks"][block_id]["interface"]), "dl_vlan": self.stored_blocks["blocks"][block_id]["match"]["vlan"]}, "actions": []}]}
		
        return payload
    
    def add_rule(self, data, payload, dpid, block_id):	    
        response = requests.post(f"http://127.0.0.1:8181/api/kytos/flow_manager/v2/flows/{dpid}", json=payload)
        if response.status_code != 202:
            raise HTTPException(400, f"Invalid request to flow_manager: {response.text}")
      
        port_no = data.get("interface")
        port_no = int(port_no)
      
        self.stored_blocks["blocks"][block_id] = {
            "switch": data["switch"],
            "interface": port_no,
            "match": data.get("match"),
	}

        linha = str(data["switch"]) + str(data.get("interface")) + str(data.get("match"))
        self.list_blocks.append(linha)
        return True, "success"
	    
    def remove_rule(self, data, payload, dpid):
        block_id = data["block_id"]
        if (block_id in self.stored_blocks["blocks"]):
            response = requests.delete(f"http://127.0.0.1:8181/api/kytos/flow_manager/v2/flows/{dpid}", json=payload)
            if response.status_code != 202:
                raise HTTPException(400, f"Invalid request to flow_manager: {response.text}")
		    
            #del self.stored_blocks["blocks"][block_id]
            #linha = str(data["switch"]) + str(data.get("interface")) + str(data.get("match"))
            linha = str(self.stored_blocks["blocks"][block_id]["switch"]) + str(self.stored_blocks["blocks"][block_id]["interface"]) + str(self.stored_blocks["blocks"][block_id]["match"])
            del self.stored_blocks["blocks"][block_id]
            self.list_blocks.remove(linha)
        return True, "success"
	    
    @rest('/v1/contention_block', methods=['POST'])
    def contention_block(self, request: Request) -> JSONResponse:
        action = 'POST'
        data = get_json_or_400(request, self.controller.loop) #access user request
        result, msg = self.validate_input(data, action)
        if not result:
            raise HTTPException(400, f"Invalid request data: {msg}")
        log.info(f"ADD BLOCK contention_block called with data={data}")
      
        dpid = data["switch"]
        block_id = uuid4().hex[:14]
        payload = self.get_payload(data, block_id, action)
	    
        if ("block_id" in data): #Para verificação se tentar inserir um ID já existente (proximo if) #NAO PRECISA
            block_id = data["block_id"]
		
        if (block_id in self.stored_blocks["blocks"]): #PRECISA TBM VERIFICAR APENAS O MATCH PARA NAO DEIXAR CRIAR #NAO PRECISA MAIS
            return JSONResponse({"result": "Index ID already exists. Contentation doesn't created"})
        else:
            linha = str(data["switch"]) + str(data.get("interface")) + str(data.get("match"))
            if (linha not in self.list_blocks):
                if (self.add_rule(data, payload, dpid, block_id)): #Rule is inserted (add_rule)
                    log.info(f"Update block list ADD={data}")  
                    return JSONResponse(f"result: Contentation created successfully ID {block_id}")
            else:
                return JSONResponse({"result": "RULE already exists in the list. Contentation doesn't created"})
      
    @rest('/v1/contention_block', methods=['DELETE'])
    def remove_contention_block(self, request: Request) -> JSONResponse:
        action = 'DELETE'
        data = get_json_or_400(request, self.controller.loop) #access user request
        result, msg = self.validate_input(data, action)
        if not result:
            raise HTTPException(400, f"Invalid request data: {msg}")
        log.info(f"DELETE BLOCK contention_block called with data={data}")
	    
        #dpid = data["switch"]
        block_id = data["block_id"]
        dpid= self.stored_blocks["blocks"][block_id]["switch"]
        payload = self.get_payload(data, block_id, action)

        if (self.remove_rule(data, payload, dpid)):
            log.info(f"Update block list DELETE={data}")
            return JSONResponse(f"result: Contention deleted successfully ID {block_id}")
        else:
            return JSONResponse({"result": "RULE doesn't deleted because not exist or some problem occurred"})

    @rest('/v1/contention_block', methods=['GET'])
    def list_contention_block(self, request: Request) -> JSONResponse:
        """List blocks performed so far."""        
        return JSONResponse({"result": self.stored_blocks})
          
            
        # 1. descrever a API REST
        # quais argumentos vamos aceitar?
        # - em qual switch vamos bloquear (mandatory)
        # - em qual porta do switch vamos bloquear (podemos bloquear em mais de uma porta? ou melhor que seja numa porta especifica e caso queria bloquear em mais de uma porta vc mandaria multiplas requisicoes?)
        #   -> o IDS vai ter uma base de mapeamento sobre onde o ataque foi visto e onde ele sera bloqueado (ou isso ficaria no proprio Kytos) -- mandatory
        # - quais os criterios de bloqueio (match fields) --  mandatory
        #   - VLAN  -- mandatory
        #   - IP de origem (v4 e v6) -- aceita mascara 192.168.0.0/24
        #   - IP de destino (v4 e v6) -- aceita mascara
        #   - Protocolo IP (tcp/UDP/ICMP/IGMP,etc)
        #   - Porta de origem L4 (src_port udp, src_port tcp)
        #   - Porta de destino L4 (dst_port udp, dst_port tcp)
        # - duracao do bloqueio (por quanto tempo essa regra vai permanecer ativa?)
        # - acao de bloquei (essa chamada já eh pra block, entao nao da acao)

        # 2. Validacao dos dados de entrada

        # 3. Criar a regra
        # --> chamar a flow_manager
