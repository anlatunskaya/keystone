from keystone.common import wsgi
from keystone.contrib.attestation import core


class AttestationExtension(wsgi.ExtensionRouter):

    PATH_PREFIX = '/OS-ATTESTATION'

    def add_routes(self, mapper):
        attestation_controller = core.AttestationController()

        mapper.connect(
            '/attestation',
            controller=attestation_controller,
            action='create_entry',
            conditions=dict(method=['POST']))
        mapper.connect(
            '/attestation/find',
            controller=attestation_controller,
            action='find_entry',
            conditions=dict(method=['PUT', 'POST']))
        mapper.connect(
            '/attestation/{entity_id}/validate',
            controller=attestation_controller,
            action='is_valid',
            conditions=dict(method=['GET']))
        mapper.connect(
            '/attestation/validate',
            controller=attestation_controller,
            action='validate',
            conditions=dict(method=['PUT', 'POST']))
        mapper.connect(
            '/attestation/{entity_id}',
            controller=attestation_controller,
            action='delete_entry',
            conditions=dict(method=['DELETE']))
        mapper.connect(
            '/attestation/{entity_id}',
            controller=attestation_controller,
            action='get_entry',
            conditions=dict(method=['GET']))