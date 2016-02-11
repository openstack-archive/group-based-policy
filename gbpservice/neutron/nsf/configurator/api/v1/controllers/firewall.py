import pecan
import sys
import json
from pecan import rest
from pecan import expose, response, request, abort, conf
from v1.handlers.rpc import FwaasRpc

import constants


class FWaasController(rest.RestController):
    """REST call handler for Firewall"""

    def __init__(self):
        self.fwaas_handler = FwaasRpc(topic=constants.FWAAS_RPC_TOPIC)
        super(FWaasController, self).__init__()

    @expose(method='POST', content_type='application/json')
    def post(self, **body):
        try:
            body = None
            if request.is_body_readable:
                body = request.json_body

            return self._create_firewall(body)
        except Exception as e:
            return json.dumps({'err_msg': e.message})

    @expose(method='PUT', content_type='application/json')
    def put(self, **body):
        try:
            body = None
            if request.is_body_readable:
                body = request.json_body

            header = request.headers
            method = header.get('Method-type')
            if method == 'UPDATE':
                return self._update_firewall(body)
            else:
                return self._delete_firewall(body)
        except Exception as e:
            return json.dumps({'err_msg': e.message})

    def _create_firewall(self, body):
        kwargs = body.get("kwargs")
        firewall = kwargs['fw']
        host = kwargs['host']
        context = kwargs['context']
        try:
            return json.dumps(
                self.fwaas_handler.create_firewall(
                    context, firewall, host))
        except Exception as e:
            return json.dumps({'err_msg': e.message})

    def _delete_firewall(self, body):
        kwargs = body.get("kwargs")
        firewall = kwargs['fw']
        host = kwargs['host']
        context = kwargs['context']
        try:
            return json.dumps(
                self.fwaas_handler.delete_firewall(
                    context, firewall, host))
        except Exception as e:
            return json.dumps({'err_msg': e.message})

    def _update_firewall(self, body):
        kwargs = body.get("kwargs")
        firewall = kwargs['fw']
        host = kwargs['host']
        context = kwargs['context']
        try:
            return json.dumps(
                self.fwaas_handler.update_firewall(
                    context, firewall, host))
        except Exception as e:
            return json.dumps({'err_msg': e.message})
