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

from keystone.openstack.common import processutils
import uuid
import base64
import shutil
import tempfile
import hashlib
import time
import datetime
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
            key_entry = session.query(AttestationKey).filter_by(id=kwargs['id']).first()
        else:
            key_entry = session.query(AttestationKey).filter_by(service_id=kwargs['service_id']).filter_by(hostname=kwargs['hostname']).first()
        result = {}
        for column in key_entry.__table__.columns:
            result[column.name] = getattr(key_entry, column.name)
        return result

    def update_key(self, id, **kwargs):
        session = self.get_session()
        with session.begin():
            key_entry = session.query(AttestationKey).get(id)
            key_entry.update(kwargs)
        return True

@dependency.requires('assignment_api', 'catalog_api')
class AttestationController(controller.V3Controller):
    def __init__(self):
        self.identity_api = identity.Manager()
        self.policy_api = policy.Manager()
        self.token_api = token.Manager()
        self.db = Attestationdb()
        super(AttestationController, self).__init__()

    def _validate(self, salted_hash, pkey, pure_hash, salt):
        try:
            tmp_dir = tempfile.mkdtemp()
            open(tmp_dir+'/key','w+').write(base64.b64decode(pkey))
            open(tmp_dir+'/purehash','w+').write(base64.b64decode(pure_hash))
            open(tmp_dir+'/nonce','w+').write(hashlib.sha1(salt).digest())
            open(tmp_dir+'/salted_hash','w+').write(base64.b64decode(salted_hash))
            processutils.execute('tpm_verifyquote', tmp_dir+'/key', tmp_dir+'/purehash', tmp_dir+'/nonce', tmp_dir+'/salted_hash')
            shutil.rmtree(tmp_dir)
            return True
        except:
            return False

    def _is_valid(self, entity_id):
        key_entry = self.db.get_key(id=entity_id)
        current_timestamp = time.time()
        if key_entry['issued_at'] != None:
            issued_timestamp = time.mktime(key_entry['issued_at'].timetuple())
        else:
            issued_timestamp = 0
        return current_timestamp - issued_timestamp < 60


    @controller.protected()
    def is_valid(self, context, entity_id):
        return { "valid":  self._is_valid(entity_id) }

    def validate(self, context, key_data):
        key_id = key_data['id']
        key_entry = self.db.get_key(id=key_data['id'])
        if key_data['salt'] == key_entry['latest_salt']:
            #we're not going to validate same salt twice
            return False
        is_valid = self._validate(key_data['salted_hash'], key_entry['pkey'], key_entry['pure_hash'], key_data['salt'])
        if is_valid:
            self.db.update_key(id = key_data['id'], salted_hash=key_data['salted_hash'], latest_salt=key_data['salt'], issued_at=datetime.datetime.now())
        return {"key_data": { "id":key_entry['id'], "uuid":key_entry['uuid'], "PCRs":key_entry['PCRs'], 'valid': is_valid}}

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
        id = self.db.add_key(key_data,service_id)
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
        hostname=key_data['hostname']
        key_entry = self.db.get_key(service_id=service_id, hostname=hostname)
        key_entry['PCRs'] = eval(key_entry['PCRs'])
        key_entry['valid'] = self._is_valid(key_entry['id'])
        return {"key_data": { "id":key_entry['id'], "uuid":key_entry['uuid'], "PCRs":key_entry['PCRs'], 'valid': key_entry['valid']}}

