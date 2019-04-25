# Copyright 2018, Qualita Seguranca e Saude Ocupacional. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
import json
import os

import pytest
import requests_mock

import esocial

from esocial import xml, client
from esocial.utils import pkcs12_data

here = os.path.dirname(os.path.abspath(__file__))
there = os.path.dirname(os.path.abspath(esocial.__file__))


def obtain_file_data(filename):
    with open(filename, 'r') as fd:
        return fd.read()


@pytest.fixture
def resources_path():
    return f'{here}/resources'


@pytest.fixture
def ws_client(resources_path, request):
    client_settings = {
        'cert_filename': os.path.join(there, 'certs', 'libesocial-cert-test.pfx'),
        'cert_password': 'cert@test',
        'employer': {
            'tpInsc': 1,
            'nrInsc': '12345678901234'
        }
    }

    if hasattr(request, 'params') and request.params.get('read_settings_file'):
        client_settings_filename = os.path.join(resources_path, '.client-settings.json')
        if os.path.exists(client_settings_filename):
            client_settings = json.loads(obtain_file_data(client_settings_filename))
        else:
            raise AssertionError(f'File {client_settings_filename} not found!')

    return client.WSClient(
        pfx_file=client_settings.get('cert_filename'),
        pfx_passw=client_settings.get('cert_password'),
        employer_id=client_settings.get('employer'),
        sender_id=client_settings.get('employer')
    )


def test_should_validate_schema(resources_path):
    # GIVEN
    event = xml.load_fromfile(os.path.join(resources_path, 'S-2220.xml'))

    # WHEN
    xml_schema = xml.XMLValidate(event)

    # THEN
    assert xml_schema.isvalid()


def test_should_sign_xml(resources_path):
    # GIVEN
    evt2220_not_signed = xml.load_fromfile(os.path.join(resources_path, 'S-2220_not_signed.xml'))

    # WHEN
    cert_data = pkcs12_data(
        cert_file=os.path.join(there, 'certs', 'libesocial-cert-test.pfx'),
        password='cert@test'
    )
    evt2220_signed = xml.sign(evt2220_not_signed, cert_data)

    # THEN
    assert xml.XMLValidate(evt2220_signed).isvalid()


def test_should_send_events_batch(ws_client, resources_path):
    # GIVEN
    event = xml.load_fromfile(f'{resources_path}/S-2220_not_signed.xml')

    ws_client.add_event(event)

    # WHEN
    with requests_mock.mock() as mock:
        url = esocial._WS_URL[ws_client.target]['send']
        mock.get(url, text=obtain_file_data(f'{resources_path}/WsEnviarLoteEventos.wsdl'))
        mock.post(url[:-5], text=obtain_file_data(f'{resources_path}/RetornoEnvioLoteEventos.xml'))

        result = ws_client.send_events_batch(1, 'ns0:EnviarLoteEventos')

    # THEN
    assert result


def test_should_retrieve_events_batch(ws_client, resources_path):
    # GIVEN
    protocol_number = 'A.B.YYYYMM.NNNNNNNNNNNNNNNNNNN'

    # WHEN
    with requests_mock.mock() as mock:
        url = esocial._WS_URL[ws_client.target]['retrieve']
        mock.get(url, text=obtain_file_data(f'{resources_path}/WsConsultarLoteEventos.wsdl'))
        mock.post(url, text=obtain_file_data(f'{resources_path}/RetornoProcessamentoLoteEventos.xml'))

        result = ws_client.retrieve_events_batch(protocol_number, 'ns0:ConsultarLoteEventos')

    # THEN
    assert result


# def test_should_obtain_employee_ids(ws_client):
#     # GIVEN
#
#     # WHEN
#     with requests_mock.mock() as mock:
#         url = esocial._WS_URL[ws_client.target]['events_ids']
#         mock.get(url, text=obtain_file_data(f'{resources_path}/WsConsultarIdentificadoresEventos.wsdl'))
#         mock.post(url, text=obtain_file_data(f'{resources_path}/RetornoProcessamentoLoteEventos.xml'))
#
#         result = ws_client.obtain_employee_ids('09887219967', '2019-03-10T00:00:00', '2019-04-10T23:59:59')
#
#     # THEN
#     assert result
#
#
# def test_should_obtain_employee_ids_real():
#     employer_id = {
#         'tpInsc': 1,
#         'nrInsc': '32712967000192'
#     }
#     ws = client.WSClient(
#         pfx_file='/home/alexandre/Documents/eCNPJ_A1_20190215_20200215_bkp.pfx',
#         pfx_passw='',
#         employer_id=employer_id,
#         sender_id=employer_id
#     )
#     result = ws.obtain_employee_ids('09887219967', '2019-04-10T00:00:00', '2019-04-25T13:30:00')
#     print(xml.dump_tostring(result, True))
#
#
# def test_should_obtain_employer_ids_real():
#     employer_id = {
#         'tpInsc': 1,
#         'nrInsc': '32712967000192'
#     }
#     ws = client.WSClient(
#         pfx_file='/home/alexandre/Documents/eCNPJ_A1_20190215_20200215_bkp.pfx',
#         pfx_passw='',
#         employer_id=employer_id,
#         sender_id=employer_id
#     )
#     result = ws.obtain_employer_ids('S-1000', '2019-03')
#     print(xml.dump_tostring(result, True))
#
#
# def test_should_download_events_by_ids_real():
#     # GIVEN
#     employer_id = {
#         'tpInsc': 1,
#         'nrInsc': '32712967000192'
#     }
#     ws = client.WSClient(
#         pfx_file='/home/alexandre/Documents/eCNPJ_A1_20190215_20200215_bkp.pfx',
#         pfx_passw='',
#         employer_id=employer_id,
#         sender_id=employer_id
#     )
#
#     events_ids = ['ID1327129670000002019032114182400001', 'ID1327129670000002019032116534600001']
#
#     # WHEN
#     result = ws.download_events_by_ids(events_ids)
#
#     # THEN
#     print(xml.dump_tostring(result, True))
#
#
# def test_should_send_events_batch_real(resources_path):
#     # GIVEN
#     evt_not_signed = xml.load_fromfile(f'{resources_path}/S-2190_not_signed.xml')
#
#     employer_id = {
#         'tpInsc': 1,
#         'nrInsc': '32712967000192'
#     }
#     ws = client.WSClient(
#         pfx_file='/home/alexandre/Documents/eCNPJ_A1_20190215_20200215_bkp.pfx',
#         pfx_passw='',
#         employer_id=employer_id,
#         sender_id=employer_id
#     )
#     ws.add_event(evt_not_signed)
#
#     # WHEN
#     result = ws.send_events_batch(1)
#
#     # THEN
#     print(xml.dump_tostring(result, True))
#
#
# def test_should_retrieve_events_batch_real(resources_path):
#     # GIVEN
#     employer_id = {
#         'tpInsc': 1,
#         'nrInsc': '32712967000192'
#     }
#     ws = client.WSClient(
#         pfx_file='/home/alexandre/Documents/eCNPJ_A1_20190215_20200215_bkp.pfx',
#         pfx_passw='',
#         employer_id=employer_id,
#         sender_id=employer_id
#     )
#
#     # WHEN
#     result = ws.retrieve_events_batch('')
#
#     # THEN
#     print(xml.dump_tostring(result, True))
