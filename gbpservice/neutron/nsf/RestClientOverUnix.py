import os
import sys
import httplib2
import httplib
import six
import six.moves.urllib.parse as urlparse
import socket


class UnixDomainHTTPConnection(httplib.HTTPConnection):

    """Connection class for HTTP over UNIX domain socket."""

    def __init__(self, host, port=None, strict=None, timeout=None,
                 proxy_info=None):
        httplib.HTTPConnection.__init__(self, host, port, strict)
        self.timeout = timeout
        self.socket_path = '/tmp/uds_socket'

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


if __name__ == "__main__":
        '''
        headers = {
            'X-Forwarded-For': remote_address,
        }

        if self.router_id:
            headers['X-Neutron-Router-ID'] = self.router_id
        else:
            headers['X-Neutron-Network-ID'] = self.network_id
        '''
        url = urlparse.urlunsplit((
            'http',
            '192.168.2.68',  # a dummy value to make the request proper
            'vpn/get_vpnservices',
            None,
            ''))

        h = httplib2.Http()
        resp, content = h.request(
            url,
            method='GET',
            headers=None,
            body=None,
            connection_type=UnixDomainHTTPConnection)

        if resp.status == 200:
            print resp
            print content
            '''
            LOG.debug(resp)
            LOG.debug(encodeutils.safe_decode(content, errors='replace'))
            response = webob.Response()
            response.status = resp.status
            response.headers['Content-Type'] = resp['content-type']
            response.body = wsgi.encode_body(content)
            return response
            '''
        elif resp.status == 400:
            print resp
            # return webob.exc.HTTPBadRequest()
        elif resp.status == 404:
            print resp
            # return webob.exc.HTTPNotFound()
        elif resp.status == 409:
            print resp
            # return webob.exc.HTTPConflict()
        elif resp.status == 500:
            print resp
            '''
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.debug(msg)
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
            '''
        else:
            raise Exception(_('Unexpected response code: %s') % resp.status)
