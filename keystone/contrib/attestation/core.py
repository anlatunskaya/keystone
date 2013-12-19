# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from keystone.common import extension
from keystone.common import manager
from keystone.common import wsgi
from keystone import config
from keystone import exception
from keystone import identity
from keystone.openstack.common import log as logging
from keystone import policy
from keystone import token
from keystone.common import dependency
import uuid

from keystone.common import sql
from keystone.common import controller
from keystone import service


CONF = config.CONF
LOG = logging.getLogger(__name__)

extension_data = {
    'name': 'Openstack Keystone host attestation API',
    'namespace': 'http://docs.openstack.org/identity/api/ext/',
    'alias': 'OS-ATTESTATION',
    'updated': '2013-07-12T12:00:0-00:00',
    'description': 'Openstack Keystone ATTESTION API.',
    'links': [
        {
            'rel': 'describedby',
            'type': 'text/html',
            'href': 'https://github.com/openstack/identity-api',
        }
    ]}
extension.register_admin_extension(extension_data['alias'], extension_data)


class AttestationKey(sql.ModelBase, sql.DictBase):
    __tablename__ = 'attestation_keys'
    attributes = ['id', 'hostname',
                  'PCRs', 'auth_type', 'service_id',
                  'uuid', 'pkey', 'pure_hash', 'latest_salt', 'salted_hash', 'issued_at', 'extra']
    id = sql.Column(sql.String(64), primary_key=True, nullable=False)
    hostname = sql.Column(sql.String(64), nullable=False)
    PCRs = sql.Column(sql.String(255), nullable=True)
    auth_type = sql.Column(sql.String(64), nullable=True)
    service_id = sql.Column(sql.String(64), sql.ForeignKey('service.id'), nullable=False, index=True)
    uuid = sql.Column(sql.String(64), nullable=False)
    pkey = sql.Column(sql.Text(), nullable=False)
    pure_hash = sql.Column(sql.Text(), nullable=False)
    latest_salt = sql.Column(sql.String(64), nullable=True)
    salted_hash = sql.Column(sql.Text(), nullable=True)
    issued_at = sql.Column(sql.DateTime(), nullable=True)
    extra = sql.Column(sql.Text(), nullable=False)


class Attestationdb(sql.Base):
    def add_key(self, key_dict, service_id):
        session = self.get_session()
        id=uuid.uuid4().hex
        with session.begin():
            key = AttestationKey(id=id,hostname=key_dict['hostname'],PCRs=str(key_dict['PCRs']),auth_type=key_dict['auth_type'],service_id=service_id,uuid=key_dict['uuid'],pkey=key_dict['pkey'],
                pure_hash=key_dict['pure_hash'],latest_salt=None,salted_hash=None,issued_at=None)
            session.add(key)
            session.flush()
        return id

    def get_key(self, **kwargs):
        session = self.get_session()
        if 'id' in kwargs:
            key_entry = session.query(AttestationKey).filter_by(service_id=kwargs['id']).first()
        else:
            key_entry = session.query(AttestationKey).filter_by(service_id=kwargs['service_id']).filter_by(hostname=kwargs['hostname']).first()
        result = {}
        for column in key_entry.__table__.columns:
            result[column.name] = getattr(key_entry, column.name)
        return result

@dependency.requires('assignment_api', 'catalog_api')
class AttestationController(controller.V3Controller):
    def __init__(self):
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        super(AttestationController, self).__init__()

    def _validate(self,id,quotedhash):
        return False

    @controller.protected()
    def create_entry(self, context, key_data):
        self.assert_admin(context)
        token_id = context.get('token_id')
        token_ref = self.token_api.get_token(token_id)
        services = self.catalog_api.list_services()
        service_id = None
        for srv in services:
          if srv['type'] == key_data['service']:
            service_id = srv['id']
        db=Attestationdb()
        id = db.add_key(key_data,service_id)
        return { "key_id": id }
    def update_entry(self, data):
        raise exception.NotImplemented()
    def delete_entry(self, data):
        raise exception.NotImplemented()
    def get_entry(self, context, entity_id):
        raise exception.NotImplemented()
    def find_entry(self, context, key_data):
        services = self.catalog_api.list_services()
        service_id = None
        for srv in services:
          if srv['type'] == key_data['service']:
            service_id = srv['id']
        db=Attestationdb()
        hostname=key_data['hostname']
        key_entry = db.get_key(service_id=service_id, hostname=hostname)
        key_entry['PCRs'] = eval(key_entry['PCRs'])
        return {"key_data":key_entry}

