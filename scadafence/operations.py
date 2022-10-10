""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json, datetime, time
from connectors.core.connector import ConnectorError, get_logger
from .constant import *

logger = get_logger('scadafence')


class SCADAfence(object):
    def __init__(self, config, *args, **kwargs):
        self.x_org = config.get('x_org')
        self.api_key = config.get('api_key')
        self.secret_key = config.get('secret_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api'.format(url)
        else:
            self.url = url + '/api'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None, json=None):
        try:
            url = self.url + url
            headers = {
                'x-org': self.x_org,
                'x-api-key': self.api_key,
                'x-api-secret': self.secret_key,
                'Content-Type': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, json=json, headers=headers,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif response.status_code == 404:
                return response.json()
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def convert_datetime_to_epoch(date_time):
    d1 = time.strptime(date_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = datetime.datetime.fromtimestamp(time.mktime(d1)).strftime('%s')
    return epoch


def create_alert(config, params):
    sf = SCADAfence(config)
    endpoint = '/alert'
    payload = check_payload(params)
    response = sf.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
    return response


def get_alerts(config, params):
    sf = SCADAfence(config)
    endpoint = '/alerts'
    sort = params.get('sort')
    order = params.get('order')
    if sort:
        params.update({'sort': SORT_DICT.get('sort')})
    if order:
        params.update({'order': ALERT_ORDER_DICT.get('order')})
    payload = check_payload(params)
    response = sf.make_rest_call(endpoint, 'GET', params=payload)
    return response


def update_alert_status(config, params):
    sf = SCADAfence(config)
    endpoint = '/alerts/{0}'.format(id)
    payload = {
        'status': params.get('status')
    }
    response = sf.make_rest_call(endpoint, 'PATCH', data=json.dumps(payload))
    return response


def get_assets(config, params):
    sf = SCADAfence(config)
    endpoint = '/assets'
    sort = params.get('sort')
    order = params.get('order')
    if sort:
        params.update({'sort': SORT_DICT.get('sort')})
    if order:
        params.update({'order': ASSET_ORDER_DICT.get('order')})
    payload = check_payload(params)
    response = sf.make_rest_call(endpoint, 'GET', params=payload)
    return response


def update_asset(config, params):
    sf = SCADAfence(config)
    id = params.pop('id')
    ip = params.pop('ip')
    endpoint = '/asset/{0}/{1}'.format(id, ip)
    payload = check_payload(params)
    response = sf.make_rest_call(endpoint, 'PATCH', data=json.dumps(payload))
    return response


def get_sites_status(config, params):
    sf = SCADAfence(config)
    endpoint = '/sites'
    payload = check_payload(params)
    response = sf.make_rest_call(endpoint, 'GET', params=payload)
    return response


def _check_health(config):
    try:
        response = get_alerts(config, params={})
        if response:
            return True
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'create_alert': create_alert,
    'get_alerts': get_alerts,
    'update_alert_status': update_alert_status,
    'get_assets': get_assets,
    'update_asset': update_asset,
    'get_sites_status': get_sites_status
}
