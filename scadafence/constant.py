""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

errors = {
    '401': 'Unauthorized, API key invalid',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}

SORT_DICT = {
    'Ascending': 'asc',
    'Descending': 'desc'
}

ALERT_ORDER_DICT = {
    'Severity': 'event_severity',
    'Site ID': 'site_id',
    'Packet Timestamp': 'packet_timestamp'
}

ASSET_ORDER_DICT = {
    'Site ID': 'site_id',
    'IP': 'ip',
    'HostName': 'hostname',
    'First Seen': 'first_seen',
    'Last Seen': 'last_seen',
    'Total Traffic Bytes': 'total_traffic_bytes'
}
