"""Main module of talitarp/contention_block Kytos Network Application."""

import requests
from kytos.core import KytosNApp, log, rest
from kytos.core import KytosEvent
from kytos.core.helpers import listen_to
from kytos.core.rest_api import (HTTPException, JSONResponse, Request,
                                 get_json_or_400)

class Main(KytosNApp):
    """Main class of talitarp/contention_block NApp.This class is the entry point for this napp."""

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

    def validate_input(self, data):
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

        expected_fields = ["ipv4_src", "ipv4_dst", "ipv6_src", "ipv6_dst", "ip_proto", "sport", "dport", "vlan"]
        for key in match:
            if key not in expected_fields:
                return False, f"Unexpected input match field: {key}"

        return True, "success"

    @rest('/v1/contention_block', methods=['POST'])
    def contention_block(self, request: Request) -> JSONResponse:
        data = get_json_or_400(request, self.controller.loop) #access user request
        result, msg = self.validate_input(data)
        if not result:
            raise HTTPException(400, f"Invalid request data: {msg}")
        log.info(f"contention_block called with data={data}")

        # Call flow_manager's REST API to create the flow
        #payload = {"flows": [{"priority": 30000, "hard_timeout": xxx, "cookie": 0xee00000000000001, "match": {"in_port": xxx, "dl_vlan": xxx, "nw_src": xxx, "nw_dst": xxx, "nw_proto": xxx}, "actions": []}]}
        payload = {"flows": [{"priority": 30000, "cookie": 0xee00000000000001, "match": {"in_port": int(data["interface"]), "dl_vlan": data["match"]["vlan"]}, "actions": []}]}
        dpid = data["switch"]

        if "ipv4_src" in data["match"]:
            payload["flows"][0]["match"]["dl_type"] = 0x800
            payload["flows"][0]["match"]["nw_src"] = data["match"]["ipv4_src"]
        if "ipv4_dst" in data["match"]:
            payload["flows"][0]["match"]["dl_type"] = 0x800
            payload["flows"][0]["match"]["nw_dst"] = data["match"]["ipv4_dst"]
        if "ip_proto" in data["match"]:
            payload["flows"][0]["match"]["nw_proto"] = data["match"]["ip_proto"]

        response = requests.post(f"http://127.0.0.1:8181/api/kytos/flow_manager/v2/flows/{dpid}", json=payload)
        if response.status_code != 202:
            raise HTTPException(400, f"Invalid request to flow_manager: {response.text}")
        return JSONResponse({"result": "contentation created successfully"})

    @rest('/v1/contention_block', methods=['DELETE'])
    def remove_contention_block(self, request: Request) -> JSONResponse:
        data = get_json_or_400(request, self.controller.loop) #access user request
        result, msg = self.validate_input(data)
        if not result:
            raise HTTPException(400, f"Invalid request data: {msg}")
        log.info(f"remove_contention_block called with data={data}")

        # Call flow_manager's REST API to create the flow
        #payload = {"flows": [{"priority": 30000, "hard_timeout": xxx, "cookie": 0xee00000000000001, "match": {"in_port": xxx, "dl_vlan": xxx, "nw_src": xxx, "nw_dst": xxx, "nw_proto": xxx}, "actions": []}]}
        payload = {"flows": [{"priority": 30000, "cookie": 0xee00000000000001, "cookie_mask": 0xffffffffffffffff, "match": {"in_port": int(data["interface"]), "dl_vlan": data["match"]["vlan"]}, "actions": []}]}
        dpid = data["switch"]

        if "ipv4_src" in data["match"]:
            payload["flows"][0]["match"]["nw_src"] = data["match"]["ipv4_src"]
        if "ipv4_dst" in data["match"]:
            payload["flows"][0]["match"]["nw_dst"] = data["match"]["ipv4_dst"]
        if "ip_proto" in data["match"]:
            payload["flows"][0]["match"]["nw_proto"] = data["match"]["ip_proto"]

        response = requests.delete(f"http://127.0.0.1:8181/api/kytos/flow_manager/v2/flows/{dpid}", json=payload)
        if response.status_code != 202:
            raise HTTPException(400, f"Invalid request to flow_manager: {response.text}")

        return JSONResponse({"result": "contention deleted successfully"})

    @rest("/v1/contention_block", methods=['GET'])
    def list_contention_block(self, _request: Request) -> JSONResponse:
        """List blocks performed so far."""
      
        data = get_json_or_400(request, self.controller.loop) #access user request
        result, msg = self.validate_input(data)
        if not result:
            raise HTTPException(400, f"Invalid request data: {msg}")
        log.info(f"list_contention_block called with data={data}")

        # Call flow_manager's REST API to create the flow
        #payload = {"flows": [{"priority": 30000, "hard_timeout": xxx, "cookie": 0xee00000000000001, "match": {"in_port": xxx, "dl_vlan": xxx, "nw_src": xxx, "nw_dst": xxx, "nw_proto": xxx}, "actions": []}]}
        payload = {"flows": [{"priority": 30000, "cookie": 0xee00000000000001, "cookie_mask": 0xffffffffffffffff, "match": {"in_port": int(data["interface"]), "dl_vlan": data["match"]["vlan"]}, "actions": []}]}
        dpid = data["switch"]

        if "ipv4_src" in data["match"]:
            payload["flows"][0]["match"]["nw_src"] = data["match"]["ipv4_src"]
        if "ipv4_dst" in data["match"]:
            payload["flows"][0]["match"]["nw_dst"] = data["match"]["ipv4_dst"]
        if "ip_proto" in data["match"]:
            payload["flows"][0]["match"]["nw_proto"] = data["match"]["ip_proto"]

        if response.status_code != 200:
            raise HTTPException(400, f"Invalid request to flow_manager: {response.text}")

        response = self.list_blocks(dpid)
        return JSONResponse(response)
          
      
      
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
