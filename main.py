"""Main module of talitarp/contention Kytos Network Application."""

import json
import requests
from uuid import uuid4

from kytos.core import KytosEvent, KytosNApp, log, rest
from kytos.core.helpers import listen_to
from kytos.core.rest_api import HTTPException, JSONResponse, Request, get_json_or_400
from napps.kytos.of_core.v0x04.flow import Action
from napps.hackinsdn.containment.of_core.v0x04.action import (
    ActionSetETHDst,
    ActionSetFieldFactory,
    ActionSetIPv4Dst,
    ActionSetIPv6Dst,
    ActionSetTCPDst,
    ActionSetUDPDst,
)
from pyof.v0x04.common.action import ActionSetField as OFActionSetField

from .settings import COOKIE_PREFIX


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
	    "redirect_to": {outport},
            "set": {set_vlan, set_ipv4_dst, set_ipv6_dst, set_tcp_dst, set_udp_dst ...}
            }
        }}
        """
        self.list_blocks = []

        # for new actions
        self.new_actions = {
            "set_ipv4_dst": ActionSetIPv4Dst,
            "set_ipv6_dst": ActionSetIPv6Dst,
            "set_tcp_dst": ActionSetTCPDst,
            "set_udp_dst": ActionSetUDPDst,
            "set_eth_dst": ActionSetETHDst,
            OFActionSetField: ActionSetFieldFactory,  # overwrite of_core definition
        }

    def execute(self):
        """This method is executed right after the setup method execution.

        You can also use this method in loop mode if you add to the above setup
        method a line like the following example:

            self.execute_as_loop(30)  # 30-second interval.

        It is not necessary in this NApp.
        """
        self.register_new_actions()

    def shutdown(self):
        """This method is executed when your napp is unloaded.

        If you have some cleanup procedure, insert it here:
            log.info('SHUTDOWN contention_block')

        It is not necessary in this NApp.
        """

    def register_new_actions(self):
        """Add new actions to kytos/of_core."""
        for name, action in self.new_actions.items():
            Action.add_action_class(name, action)

    def validate_input(self, data, type):
        if type == "POST":
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

            expected_fields = [
                "ipv4_src",
                "ipv4_dst",
                "ipv6_src",
                "ipv6_dst",
                "ip_proto",
                "sport",
                "dport",
                "vlan",
                "tcp_src",
                "tcp_dst",
                "udp_src",
                "udp_dst",
                "mac_src",
                "mac_dst",
            ]
            for key in match:
                if key not in expected_fields:
                    return False, f"Unexpected input match field: {key}"

            # check matching fields: TCP or UDP (Mandatory IPV4 or IPV6 specification)
            if (
                "tcp_src" in match
                or "tcp_dst" in match
                or "udp_src" in match
                or "udp_dst" in match
            ):
                if (
                    "ipv4_src" not in match
                    or "ipv4_dst" not in match
                    or "ipv6_src" not in match
                    or "ipv6_dst" not in match
                ):
                    return False, f"Missing mandatory ipv4 or ipv6 on match"

            # Only Redirect Contention, the outport redirect is specification (mandatory).
            if "redirect_to" in data:
                redirect_to = data.get("redirect_to")
                if "outport" not in redirect_to:
                    return False, f"Missing mandatory field on redirect_to: outport"

            # Only on Redirect Contention, some fields are expected if exists change in pack data.
            expected_fields2 = [
                "set_vlan",
                "set_ipv4_dst",
                "set_ipv6_dst",
                "set_tcp_dst",
                "set_udp_dst",
                "set_mac_dst",
            ]

            if "set" in data:
                set = data.get("set")
                for key in set:
                    if key not in expected_fields2:
                        return False, f"Unexpected input set field: {key}"

        if type == "DELETE":
            if "block_id" not in data:
                return False, "Missing mandatory field block_id on data"

        return True, "success"

    def get_payload(self, data, block_id, type):
        # Call flow_manager's REST API to create the flow
        # payload = {"flows": [{"priority": 30000, "hard_timeout": xxx, "cookie": 0xee00000000000001, "match": {"in_port": xxx, "dl_vlan": xxx, "nw_src": xxx, "nw_dst": xxx, "nw_proto": xxx, "ipv6_src"=xxx, "ipv6_dst"=xxx, "tcp_src"=xxx, "tcp_dst"=xxx, "udp_src"=xxx, "udp_dst"=xxx}, "actions": []}]}

        cookie = COOKIE_PREFIX + block_id
        cookie = int(cookie, 16)

        if type == "POST":
            if "redirect_to" not in data:  # It's a block contention. Action is empty
                payload = {
                    "flows": [
                        {
                            "priority": 30000,
                            "cookie": cookie,
                            "match": {
                                "in_port": int(data["interface"]),
                                "dl_vlan": data["match"]["vlan"],
                            },
                            "actions": [],
                        }
                    ]
                }

            if "redirect_to" in data:  # It's a redirect contention. Action isn't empty
                # Is necessary verificy if exists more fields ("set_vlan", set_ipv4_dst", "set_ipv6_dst", "set_tcp_dst", "set_udp_dst", "set_mac_dst") on set.

                if (
                    "set" not in data
                ):  # The rule is redirect contention and doesn't exists modify pack data.
                    redirect_to = data["redirect_to"]["outport"]
                    payload = {
                        "flows": [
                            {
                                "priority": 30000,
                                "cookie": cookie,
                                "match": {
                                    "in_port": int(data["interface"]),
                                    "dl_vlan": data["match"]["vlan"],
                                },
                                "actions": [
                                    {"action_type": "output", "port": redirect_to}
                                ],
                            }
                        ]
                    }

                if (
                    "set" in data
                ):  # The rule is redirect contention and exists modify pack data. Before redirect for outport especify, is necessary to modify the pack data.
                    set = data.get("set")
                    redirect_to = data["redirect_to"][
                        "outport"
                    ]  # Add an action to send to the specified port (last action)

                    if "set_vlan" in set:
                        # adicionar uma action no flow que será enviado para flow_manager com action_type: set_vlan, vlanid= vlan que o usuário pediu
                        vlan = data["set"]["set_vlan"]
                        payload = {
                            "flows": [
                                {
                                    "priority": 30000,
                                    "cookie": cookie,
                                    "match": {
                                        "in_port": int(data["interface"]),
                                        "dl_vlan": data["match"]["vlan"],
                                    },
                                    "actions": [
                                        {"action_type": "set_vlan", "vlan_id": vlan},
                                        {"action_type": "output", "port": redirect_to},
                                    ],
                                }
                            ]
                        }
                    if "set_ipv4_dst" in set:
                        # action_type: set_ipv4_dst, ipv4_dst= ipv4_dst que o usuário pediu
                        ipv4_dst = data["set"]["set_ipv4_dst"]
                        payload = {
                            "flows": [
                                {
                                    "priority": 30000,
                                    "cookie": cookie,
                                    "match": {
                                        "in_port": int(data["interface"]),
                                        "dl_vlan": data["match"]["vlan"],
                                    },
                                    "actions": [
                                        {
                                            "action_type": "set_ipv4_dst",
                                            "ipv4_dst": ipv4_dst,
                                        },
                                        {"action_type": "output", "port": redirect_to},
                                    ],
                                }
                            ]
                        }
                    if "set_ipv6_dst" in set:
                        # action_type: set_ipv6_dst, ipv6_dst= ipv6_dst que o usuário pediu
                        ipv6_dst = data["set"]["set_ipv6_dst"]
                        payload = {
                            "flows": [
                                {
                                    "priority": 30000,
                                    "cookie": cookie,
                                    "match": {
                                        "in_port": int(data["interface"]),
                                        "dl_vlan": data["match"]["vlan"],
                                    },
                                    "actions": [
                                        {
                                            "action_type": "set_ipv6_dst",
                                            "ipv6_dst": ipv6_dst,
                                        },
                                        {"action_type": "output", "port": redirect_to},
                                    ],
                                }
                            ]
                        }
                    if "set_tcp_dst" in set:
                        # action_type: set_tcp_dst, tcp_dst= tcp_dst que o usuário pediu
                        tcp_dst = data["set"]["set_tcp_dst"]
                        payload = {
                            "flows": [
                                {
                                    "priority": 30000,
                                    "cookie": cookie,
                                    "match": {
                                        "in_port": int(data["interface"]),
                                        "dl_vlan": data["match"]["vlan"],
                                    },
                                    "actions": [
                                        {
                                            "action_type": "set_tcp_dst",
                                            "tcp_dst": tcp_dst,
                                        },
                                        {"action_type": "output", "port": redirect_to},
                                    ],
                                }
                            ]
                        }
                    if "set_udp_dst" in set:
                        # action_type: set_udp_dst, udp_dst= udp_dst que o usuário pediu
                        udp_dst = data["set"]["set_udp_dst"]
                        payload = {
                            "flows": [
                                {
                                    "priority": 30000,
                                    "cookie": cookie,
                                    "match": {
                                        "in_port": int(data["interface"]),
                                        "dl_vlan": data["match"]["vlan"],
                                    },
                                    "actions": [
                                        {
                                            "action_type": "set_udp_dst",
                                            "udp_dst": udp_dst,
                                        },
                                        {"action_type": "output", "port": redirect_to},
                                    ],
                                }
                            ]
                        }
                    if "set_mac_dst" in set:
                        # action_type: set_mac_dst, mac_dst= mac_dst que o usuário pediu
                        mac_dst = data["set"]["set_mac_dst"]
                        payload = {
                            "flows": [
                                {
                                    "priority": 30000,
                                    "cookie": cookie,
                                    "match": {
                                        "in_port": int(data["interface"]),
                                        "dl_vlan": data["match"]["vlan"],
                                    },
                                    "actions": [
                                        {
                                            "action_type": "set_mac_dst",
                                            "mac_dst": mac_dst,
                                        },
                                        {"action_type": "output", "port": redirect_to},
                                    ],
                                }
                            ]
                        }

            if "ipv4_src" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x800
                payload["flows"][0]["match"]["nw_src"] = data["match"]["ipv4_src"]
            if "ipv4_dst" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x800
                payload["flows"][0]["match"]["nw_dst"] = data["match"]["ipv4_dst"]
            if "ipv6_src" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x86DD
                payload["flows"][0]["match"]["ipv6_src"] = data["match"]["ipv6_src"]
            if "ipv6_dst" in data["match"]:
                payload["flows"][0]["match"]["dl_type"] = 0x86DD
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
            if "mac_src" in data["match"]:
                payload["flows"][0]["match"]["dl_src"] = data["match"]["mac_src"]
            if "mac_dst" in data["match"]:
                payload["flows"][0]["match"]["dl_dst"] = data["match"]["mac_dst"]

            # Considerando uma ação de redirect modificando os campos do pacote, podemos ter solicitações de modificações do campo:
            # "set_ipv4_dst", "set_ipv6_dst", "set_tcp_dst", "set_udp_dst", "set_mac_dst"

        if type == "DELETE":
            if "redirect_to" not in self.stored_blocks["blocks"][block_id]:  # It's a block contention.
                payload = {
                    "flows": [
                        {
                            "priority": 30000,
                            "cookie": cookie,
                            "cookie_mask": 0xFFFFFFFFFFFFFFFF,
                            "match": {
                                "in_port": int(
                                    self.stored_blocks["blocks"][block_id]["interface"]
                                ),
                                "dl_vlan": self.stored_blocks["blocks"][block_id][
                                    "match"
                                ]["vlan"],
                            },
                            "actions": [],
                        }
                    ]
                }
            if "redirect_to" in self.stored_blocks["blocks"][block_id]:  # It's a redirect contention.
                redirect_to = self.stored_blocks["blocks"][block_id]["redirect_to"][
                    "outport"
                ]
                payload = {
                    "flows": [
                        {
                            "priority": 30000,
                            "cookie": cookie,
                            "cookie_mask": 0xFFFFFFFFFFFFFFFF,
                            "match": {
                                "in_port": int(
                                    self.stored_blocks["blocks"][block_id]["interface"]
                                ),
                                "dl_vlan": self.stored_blocks["blocks"][block_id][
                                    "match"
                                ]["vlan"],
                            },
                            "actions": [{"action_type": "output", "port": redirect_to}],
                        }
                    ]
                }

        return payload

    def add_rule(self, data, payload, dpid, block_id, linha):
        response = requests.post(
            f"http://127.0.0.1:8181/api/kytos/flow_manager/v2/flows/{dpid}",
            json=payload,
        )
        if response.status_code != 202:
            raise HTTPException(
                400, f"Invalid request to flow_manager: {response.text}"
            )

        port_no = data.get("interface")
        port_no = int(port_no)

        if "redirect_to" not in data:
            self.stored_blocks["blocks"][block_id] = {
                "switch": data["switch"],
                "interface": port_no,
                "match": data.get("match"),
            }

        if "redirect_to" in data:
            self.stored_blocks["blocks"][block_id] = {
                "switch": data["switch"],
                "interface": port_no,
                "match": data.get("match"),
                "redirect_to": data.get("redirect_to"),
            }
        self.list_blocks.append(linha)
        return True, "success"

    def remove_rule(self, block_id, payload, dpid):
        if block_id in self.stored_blocks["blocks"]:
            response = requests.delete(
                f"http://127.0.0.1:8181/api/kytos/flow_manager/v2/flows/{dpid}",
                json=payload,
            )
            if response.status_code != 202:
                raise HTTPException(
                    400, f"Invalid request to flow_manager: {response.text}"
                )

            linha = (
                str(self.stored_blocks["blocks"][block_id]["switch"])
                + str(self.stored_blocks["blocks"][block_id]["interface"])
                + str(self.stored_blocks["blocks"][block_id]["match"])
            )
            del self.stored_blocks["blocks"][block_id]
            self.list_blocks.remove(linha)

        return True, "success"

    @rest("/v1/", methods=["POST"])
    def contention_post(self, request: Request) -> JSONResponse:
        type = "POST"
        data = get_json_or_400(request, self.controller.loop)  # access user request
        result, msg = self.validate_input(data, type)
        if not result:
            raise HTTPException(400, f"Invalid request data: {msg}")
        log.info(f"ADD REDIRECT contention called with data={data}")

        dpid = data["switch"]
        block_id = uuid4().hex[:14]
        payload = self.get_payload(data, block_id, type)

        if (
            "block_id" in data
        ):  # Para verificação se tentar inserir um ID já existente (proximo if) #NAO PRECISA. OU PENSAR EM UPDATE (?)
            block_id = data["block_id"]

        if block_id in self.stored_blocks["blocks"]:  # NAO PRECISA MAIS.
            raise HTTPException(400, "Fail to create containment: ID already exists.")
        else:
            # linha = str(data["switch"]) + str(data.get("interface")) + str(data.get("match")) + str(data.get("redirect_to"))
            linha = (
                str(data["switch"])
                + str(data.get("interface"))
                + str(data.get("match"))
            )  # eu guardo na lista de controle apenas ate o match. Pois é a regra de forma mais geral.
            if linha not in self.list_blocks:
                if self.add_rule(
                    data, payload, dpid, block_id, linha
                ):  # Rule is inserted (add_rule)
                    log.info(f"Update contention list ADD={data}")
                    return JSONResponse({"containment_id": block_id})
            else:
                raise HTTPException(400, "Fail to create containment: RULE already exists in the list.")

    @rest("/v1/{containment_id}", methods=["DELETE"])
    def contention_remove(self, request: Request) -> JSONResponse:
        """Remove a containment."""
        containment_id = request.path_params["containment_id"]
        if containment_id not in self.stored_blocks["blocks"]:
            log.info(f"Invalid DELETE containment {containment_id}")
            raise HTTPException(404, f"Invalid containment ID (not found)")

        log.info(f"DELETE containment {containment_id}")

        dpid = self.stored_blocks["blocks"][containment_id]["switch"]
        payload = self.get_payload({}, containment_id, "DELETE")

        if self.remove_rule(containment_id, payload, dpid):
            log.info(f"Containment DELETE successfully {containment_id}")
            return JSONResponse("Containment deleted successfully")
        else:
            raise HTTPException(400, "Fail to delete containment, check logs.")

    @rest("/v1/", methods=["GET"])
    def list_contention(self, request: Request) -> JSONResponse:
        """List contentions performed so far."""
        return JSONResponse(self.stored_blocks)

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
