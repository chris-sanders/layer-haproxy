#!/usr/bin/python3
import pytest
import mock

from collections import defaultdict


@pytest.fixture
def config():
    defaults = {'mode': 'http',
                'urlbase': '/test',
                'rewrite-path': None,
                'acl-local': None,
                'subdomain': None,
                'group_id': None,
                'external_port': 80,
                'internal_host': 'test-host',
                'internal_port': 8000,
                'check': True,
                }
    return defaultdict(lambda: None, defaults)


@pytest.fixture
def mock_crontab(monkeypatch):
    mock_cron = mock.MagicMock()
    monkeypatch.setattr('libhaproxy.CronTab', mock_cron)
    monkeypatch.setattr('libhaproxy.hookenv.local_unit', lambda: 'mock-local/0')
    # monkeypatch.setattr('libhaproxy.hookenv.charm_dir', lambda: '/mock/charm/dir')
    return mock_cron


@pytest.fixture
def cert(monkeypatch):
    normal_open = open

    def wrapper(*args, **kwargs):
        content = None
        if args[0] == '/etc/letsencrypt/live/mock/fullchain.pem':
            content = 'fullchain.pem\n'
            if 'b' in args[1]:
                content = bytes(content, encoding='utf8')
        elif args[0] == '/etc/letsencrypt/live/mock/privkey.pem':
            content = 'privkey.pem\n'
            if 'b' in args[1]:
                content = bytes(content, encoding='utf8')
        else:
            file_object = normal_open(*args)
            return file_object
        file_object = mock.mock_open(read_data=content).return_value
        file_object.__iter__.return_value = content.splitlines(True)
        return file_object

    monkeypatch.setattr('builtins.open', wrapper)


@pytest.fixture
def mock_layers(monkeypatch):
    import sys
    sys.modules["charms.layer"] = mock.Mock()
    sys.modules["reactive"] = mock.Mock()
    sys.modules["reactive.letsencrypt"] = mock.Mock()
    monkeypatch.setattr('libhaproxy.letsencrypt.register_domains', lambda: 0)
    monkeypatch.setattr('libhaproxy.letsencrypt.renew', mock.Mock())

    def options(layer):
        if layer == 'letsencrypt':
            options = {'port': 9999}
            return options
        else:
            return None

    monkeypatch.setattr('libhaproxy.layer.options', options)


@pytest.fixture
def mock_hookenv_config(monkeypatch):
    import yaml

    def mock_config():
        cfg = {}
        yml = yaml.load(open('./config.yaml'))

        # Load all defaults
        for key, value in yml['options'].items():
            cfg[key] = value['default']

        # Manually add cfg from other layers
        cfg['letsencrypt-domains'] = 'mock'
        return cfg

    monkeypatch.setattr('libhaproxy.hookenv.config', mock_config)


@pytest.fixture
def mock_service_reload(monkeypatch):
    monkeypatch.setattr('libhaproxy.host.service_reload', lambda x: None)


@pytest.fixture
def mock_remote_unit(monkeypatch):
    monkeypatch.setattr('libhaproxy.hookenv.remote_unit', lambda: 'unit-mock/0')


@pytest.fixture
def mock_ports(monkeypatch, open_ports=''):

    def mports(*args, **kwargs):
        if args[0][0] == "opened-ports":
            return bytes(mports.open_ports, encoding='utf8')
        elif args[0][0] == "open-port":
            if args[0][1].lower() not in mports.open_ports:
                mports.open_ports = mports.open_ports + args[0][1].lower() + '\n'
            return bytes(mports.open_ports, encoding='utf8')
        elif args[0][0] == "close-port":
            mports.open_ports = mports.open_ports.replace(args[0][1].lower() + '\n', '')
            return bytes(mports.open_ports, encoding='utf8')
        else:
            print("subprocess called with: {}".format(args[0]))
            return None
    mports.open_ports = open_ports

    monkeypatch.setattr('libhaproxy.subprocess.check_output', mports)
    monkeypatch.setattr('libhaproxy.subprocess.check_call', mports)
    # Wrapping hides the open_ports attribute
    # monkeypatch.setattr('libhaproxy.subprocess.check_output',
    #                     mock.Mock(spec=mports, wraps=mports))
    # monkeypatch.setattr('libhaproxy.subprocess.check_call',
    #                     mock.Mock(spec=mports, wraps=mports))


@pytest.fixture
def mock_charm_dir(monkeypatch):
    monkeypatch.setattr('libhaproxy.hookenv.charm_dir', lambda: '/mock/charm/dir')


@pytest.fixture
# def ph(pyhaproxy, tmpdir, mock_ports, mock_service_reload, mock_charm_dir, monkeypatch):
def ph(tmpdir, mock_layers, mock_hookenv_config, mock_ports, mock_service_reload, mock_charm_dir, monkeypatch):
    from libhaproxy import ProxyHelper
    ph = ProxyHelper()

    # Patch the proxy_config to a tmpfile
    cfg_file = tmpdir.join("haproxy.cfg")
    with open('./tests/unit/haproxy.cfg', 'r') as src_file:
        cfg_file.write(src_file.read())
    ph.proxy_config_file = cfg_file.strpath

    # Patch the combined cert file to a tmpfile
    crt_file = tmpdir.join("mock.pem")
    ph.cert_file = crt_file.strpath

    # Any other functions that load PH will get this version
    monkeypatch.setattr('libhaproxy.ProxyHelper', lambda: ph)

    return ph
