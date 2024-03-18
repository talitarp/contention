"""Main module of talitarp/kytosContainment Kytos Network Application.
"""

from flask import jsonify, request
from kytos.core import KytosNApp, log, rest
from kytos.core import KytosEvent
from kytos.core.helpers import listen_to

class Main(KytosNApp):
    """Main class of talitarp/kytosContainment NApp.

    This class is the entry point for this napp.
    """

    def setup(self):
        log.info('SETUP kytosContainment')

    def execute(self):
        """Execute once when the napp is running."""
        log.info('EXECUTE kytosContainment')

    def shutdown(self):
        """Execute when your napp is unloaded.

        If you have some cleanup procedure, insert it here.
        """
        log.info('SHUTDOWN kytosContainment')

    @rest('/v1/', methods=['GET'])
    def handle_get(self):
        """Endpoint to return nothing.
        """
        log.info('GET /v1/kytosContainment')
        return jsonify({}), 200

    @listen_to('.*.switch.(new|reconnected)')
    def handle_new_switch(self, event):
        """ Handle the event of a new created switch
        """
        log.info(f'handle_new_switch event={event} content={event.content}')

    @listen_to('.*.connection.lost')
    def handle_switch_conn_lost(self, event):
        """ Handle the event of switch's connection lost
        """
        log.info(f'handle_switch_conn_lost event={event} content={event.content}')

    @listen_to('.*.switch.interface.created')
    def handle_interface_created(self, event):
        """ Handle the event of a interface created
        """
        log.info(f'handle_interface_created event={event} content={event.content}')
