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
import os
import datetime
import requests
import esocial

from urllib3.util.ssl_ import create_urllib3_context
from requests.adapters import HTTPAdapter

from esocial import xml
from esocial.utils import pkcs12_data

from zeep import Client
from zeep.transports import Transport

from lxml import etree


here = os.path.abspath(os.path.dirname(__file__))
serpro_ca_bundle = os.path.join(here, 'certs', 'serpro_chain_full.pem')


class CustomHTTPSAdapter(HTTPAdapter):
    def __init__(self, ctx_options=None):
        self.ctx_options = ctx_options
        super(CustomHTTPSAdapter, self).__init__()

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        if self.ctx_options is not None:
            # Probably there is a better (pythonic) way to setting this up
            context._ctx.use_certificate(self.ctx_options.get('cert'))
            context._ctx.use_privatekey(self.ctx_options.get('key'))
            context._ctx.load_verify_locations(self.ctx_options.get('cafile'))
        kwargs['ssl_context'] = context
        return super(CustomHTTPSAdapter, self).init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        context = create_urllib3_context()
        if self.ctx_options is not None:
            context._ctx.use_certificate(self.ctx_options.get('cert'))
            context._ctx.use_privatekey(self.ctx_options.get('key'))
            context._ctx.load_verify_locations(self.ctx_options.get('cafile'))
        kwargs['ssl_context'] = context
        return super(CustomHTTPSAdapter, self).proxy_manager_for(*args, **kwargs)


class WSClient(object):
    def __init__(
        self,
        employer_id=None,
        sender_id=None,
        pfx_file=None,
        pfx_passw=None,
        ca_file=serpro_ca_bundle,
        target=esocial._TARGET
    ):
        self.ca_file = ca_file
        if pfx_file is not None:
            self.cert_data = pkcs12_data(pfx_file, pfx_passw)
        else:
            self.cert_data = None
        self.batch = []
        self.event_ids = []
        self.max_batch_size = 50
        self.employer_id = employer_id
        self.sender_id = sender_id
        self.target = target

    def _connect(self, url):
        transport_session = requests.Session()
        transport_session.mount(
            'https://',
            CustomHTTPSAdapter(
                ctx_options={
                    'cert': self.cert_data['cert'],
                    'key': self.cert_data['key'],
                    'cafile': self.ca_file
                }
            )
        )
        ws_transport = Transport(session=transport_session)
        return Client(
            url,
            transport=ws_transport
        )

    @staticmethod
    def _check_identity_number(employer_id):
        if employer_id.get('use_full') or employer_id.get('tpInsc') == 2:
            return employer_id['nrInsc']

        return employer_id['nrInsc'][:8]

    def _event_id(self):
        id_prefix = 'ID{}{:0<14}{}'.format(
            self.employer_id.get('tpInsc'),
            self._check_identity_number(self.employer_id),
            datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        )
        self.event_ids.append(id_prefix)
        Q = self.event_ids.count(id_prefix)
        return '{}{:0>5}'.format(id_prefix, Q)

    def clear_batch(self):
        self.batch = []
        self.event_ids = []

    def add_event(self, event):
        if not isinstance(event, etree._ElementTree):
            raise ValueError('Not an ElementTree instance!')

        if not (self.employer_id and self.sender_id and self.cert_data):
            raise Exception(
                'In order to add events to a batch, employer_id, sender_id, pfx_file and pfx_passw are needed!')

        if len(self.batch) < self.max_batch_size:
            # Normally, the element with Id attribute is the first one
            event.getroot().getchildren()[0].set('Id', self._event_id())
            # Signing...
            event_signed = xml.sign(event, self.cert_data)
            # Validating
            xml.XMLValidate(event_signed).validate()
            # Adding the event to batch
            self.batch.append(event_signed)
        else:
            raise Exception('More than {} events per batch is not permitted!'.format(self.max_batch_size))

    def _make_send_envelop(self, group_id):
        xmlns = 'http://www.esocial.gov.br/schema/lote/eventos/envio/v{}'
        version = esocial.__xsd_versions__['send']['version'].replace('.', '_')
        xmlns = xmlns.format(version)
        nsmap = {None: xmlns}
        batch_envelop = xml.create_root_element('eSocial', ns=nsmap)
        xml.add_element(batch_envelop, None, 'envioLoteEventos', grupo=str(group_id), ns=nsmap)
        xml.add_element(batch_envelop, 'envioLoteEventos', 'ideEmpregador', ns=nsmap)
        xml.add_element(
            batch_envelop,
            'envioLoteEventos/ideEmpregador',
            'tpInsc',
            text=str(self.employer_id['tpInsc']),
            ns=nsmap,
        )
        xml.add_element(
            batch_envelop,
            'envioLoteEventos/ideEmpregador',
            'nrInsc',
            text=str(self._check_identity_number(self.employer_id)),
            ns=nsmap
        )
        xml.add_element(batch_envelop, 'envioLoteEventos', 'ideTransmissor', ns=nsmap)
        xml.add_element(
            batch_envelop,
            'envioLoteEventos/ideTransmissor',
            'tpInsc',
            text=str(self.sender_id['tpInsc']),
            ns=nsmap
        )
        xml.add_element(
            batch_envelop,
            'envioLoteEventos/ideTransmissor',
            'nrInsc',
            text=str(self.sender_id['nrInsc']),
            ns=nsmap
        )
        xml.add_element(batch_envelop, 'envioLoteEventos', 'eventos', ns=nsmap)
        for event in self.batch:
            # Getting the Id attribute
            event_tag = event.getroot()
            event_id = event_tag.getchildren()[0].get('Id')
            # Adding the event XML
            event_root = xml.add_element(
                batch_envelop,
                'envioLoteEventos/eventos',
                'evento',
                Id=event_id,
                ns=nsmap
            )
            event_root.append(event_tag)
        return batch_envelop

    def _make_retrieve_envelop(self, protocol_number):
        xmlns = 'http://www.esocial.gov.br/schema/lote/eventos/envio/consulta/retornoProcessamento/v{}'
        version = esocial.__xsd_versions__['retrieve']['version'].replace('.', '_')
        xmlns = xmlns.format(version)
        nsmap = {None: xmlns}
        envelop = xml.create_root_element('eSocial', ns=nsmap)
        xml.add_element(envelop, None, 'consultaLoteEventos', ns=nsmap)
        xml.add_element(envelop, 'consultaLoteEventos', 'protocoloEnvio', text=str(protocol_number), ns=nsmap)
        return envelop

    def _xsd(self, which):
        version = esocial.__xsd_versions__[which]['version'].replace('.', '_')
        xsd_file = esocial.__xsd_versions__[which]['xsd'].format(version)
        xsd_file = os.path.join(here, 'xsd', xsd_file)
        return xml.xsd_fromfile(xsd_file)

    def validate_envelop(self, which, envelop):
        xmlschema = self._xsd(which)
        element_test = envelop
        if not isinstance(envelop, etree._ElementTree):
            element_test = etree.ElementTree(envelop)

        return xml.XMLValidate(element_test, xsd=xmlschema).isvalid()

    def send_events_batch(self, group_id=1, element_name='ns1:EnviarLoteEventos'):
        batch_to_send = self._make_send_envelop(group_id)
        self.validate_envelop('send', batch_to_send)

        # If no exception, batch XML is valid
        url = esocial._WS_URL[self.target]['send']
        ws = self._connect(url)

        BatchElement = ws.get_element(element_name)
        result = ws.service.EnviarLoteEventos(BatchElement(loteEventos=batch_to_send))
        del ws

        # Result is a lxml Element object
        return result

    def retrieve_events_batch(self, protocol_number, element_name='ns1:ConsultarLoteEventos'):
        batch_to_search = self._make_retrieve_envelop(protocol_number)
        self.validate_envelop('retrieve', batch_to_search)

        # if no exception, protocol XML is valid
        url = esocial._WS_URL[self.target]['retrieve']
        ws = self._connect(url)

        SearchElement = ws.get_element(element_name)
        result = ws.service.ConsultarLoteEventos(SearchElement(consulta=batch_to_search))
        del ws

        return result

    def _make_employer_ids_envelop(self, event_id, year):
        xmlns = "http://www.esocial.gov.br/schema/consulta/identificadores-eventos/empregador/v{}"
        version = esocial.__xsd_versions__['view_employer_events_ids']['version'].replace('.', '_')
        xmlns = xmlns.format(version)
        nsmap = {None: xmlns}
        envelop = xml.create_root_element('eSocial', ns=nsmap)
        xml.add_element(envelop, None, 'consultaIdentificadoresEvts', ns=nsmap)
        xml.add_element(envelop, 'consultaIdentificadoresEvts', 'ideEmpregador', ns=nsmap)
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/ideEmpregador',
            'tpInsc',
            text=str(self.employer_id['tpInsc']),
            ns=nsmap
        )
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/ideEmpregador',
            'nrInsc',
            text=str(self._check_identity_number(self.employer_id)),
            ns=nsmap
        )
        xml.add_element(envelop, 'consultaIdentificadoresEvts', 'consultaEvtsEmpregador', ns=nsmap)
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/consultaEvtsEmpregador',
            'tpEvt',
            text=event_id,
            ns=nsmap
        )
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/consultaEvtsEmpregador',
            'perApur',
            text=year,
            ns=nsmap
        )
        return envelop

    def obtain_employer_ids(self, event_id, year):
        employer_ids_envelop = self._make_employer_ids_envelop(event_id, year)
        employer_ids_envelop = xml.sign(employer_ids_envelop.getroottree(), self.cert_data)
        self.validate_envelop('view_employer_events_ids', employer_ids_envelop)

        url = esocial._WS_URL[self.target]['events_ids']
        ws = self._connect(url)

        result = ws.service.ConsultarIdentificadoresEventosEmpregador(
            consultaEventosEmpregador=employer_ids_envelop.getroot())
        del ws

        return result

    def _make_employee_ids_envelop(self, social_security_number, start_date, end_date):
        xmlns = 'http://www.esocial.gov.br/schema/consulta/identificadores-eventos/trabalhador/v{}'

        version = esocial.__xsd_versions__['view_employee_events_ids']['version'].replace('.', '_')
        xmlns = xmlns.format(version)
        nsmap = {None: xmlns}
        envelop = xml.create_root_element('eSocial', ns=nsmap)
        xml.add_element(envelop, None, 'consultaIdentificadoresEvts', ns=nsmap)
        xml.add_element(envelop, 'consultaIdentificadoresEvts', 'ideEmpregador', ns=nsmap)
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/ideEmpregador',
            'tpInsc',
            text=str(self.employer_id['tpInsc']),
            ns=nsmap
        )
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/ideEmpregador',
            'nrInsc',
            text=str(self._check_identity_number(self.employer_id)),
            ns=nsmap
        )
        xml.add_element(envelop, 'consultaIdentificadoresEvts', 'consultaEvtsTrabalhador', ns=nsmap)
        xml.add_element(
            envelop,
            'consultaIdentificadoresEvts/consultaEvtsTrabalhador',
            'cpfTrab',
            text=str(social_security_number),
            ns=nsmap
        )
        xml.add_element(
            envelop, 'consultaIdentificadoresEvts/consultaEvtsTrabalhador', 'dtIni', text=start_date, ns=nsmap)
        xml.add_element(
            envelop, 'consultaIdentificadoresEvts/consultaEvtsTrabalhador', 'dtFim', text=end_date, ns=nsmap)

        return envelop

    def obtain_employee_ids(self, social_security_number, start_date, end_date):
        employee_ids_envelop = self._make_employee_ids_envelop(social_security_number, start_date, end_date)
        employee_ids_envelop = xml.sign(employee_ids_envelop.getroottree(), self.cert_data)
        employee_ids_envelop = employee_ids_envelop.getroot()
        self.validate_envelop('view_employee_events_ids', employee_ids_envelop)

        url = esocial._WS_URL[self.target]['events_ids']
        ws = self._connect(url)
        result = ws.service.ConsultarIdentificadoresEventosTrabalhador(consultaEventosTrabalhador=employee_ids_envelop)
        del ws

        return result

    def _make_download_events_ids_envelop(self, events_ids):
        version = esocial.__xsd_versions__['download_events_by_ids']['version'].replace('.', '_')
        xmlns = f'http://www.esocial.gov.br/schema/download/solicitacao/id/v{version}'
        nsmap = {None: xmlns}
        envelop = xml.create_root_element('eSocial', ns=nsmap)
        xml.add_element(envelop, None, 'download', ns=nsmap)
        xml.add_element(envelop, 'download', 'ideEmpregador', ns=nsmap)
        xml.add_element(
            envelop,
            'download/ideEmpregador',
            'tpInsc',
            text=str(self.employer_id['tpInsc']),
            ns=nsmap,
        )
        xml.add_element(
            envelop,
            'download/ideEmpregador',
            'nrInsc',
            text=str(self._check_identity_number(self.employer_id)),
            ns=nsmap
        )
        xml.add_element(envelop, 'download', 'solicDownloadEvtsPorId', ns=nsmap)

        for event_id in events_ids:
            xml.add_element(envelop, 'download/solicDownloadEvtsPorId', 'id', text=str(event_id), ns=nsmap)

        return envelop

    def download_events_by_ids(self, events_ids):
        download_ids_envelop = self._make_download_events_ids_envelop(events_ids)
        download_ids_envelop = xml.sign(download_ids_envelop.getroottree(), self.cert_data)
        self.validate_envelop('download_events_by_ids', download_ids_envelop)

        url = esocial._WS_URL[self.target]['download']
        ws = self._connect(url)
        download_ids_envelop = download_ids_envelop.getroot()

        result = ws.service.SolicitarDownloadEventosPorId(solicitacao=download_ids_envelop)
        del ws

        return result

