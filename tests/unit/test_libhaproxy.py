#!/usr/bin/python3
"""Test the helper library used by the charm."""
import os


def test_pytest():
    """Test pytest works."""
    assert True


def test_ph(ph):
    """Test the ph fixture works to load charm configs."""
    assert isinstance(ph.charm_config, dict)


def test_proxy_config(ph):
    """Check that default proxy config can be read."""
    default_keywords = ["httplog", "dontlognull"]
    for option in ph.proxy_config.defaults[0].options():
        assert option.keyword in default_keywords


def test_add_timeout_tunnel(ph):
    """Test adding the tunnel timeout."""
    test_keyword = "timeout tunnel"
    defaults = ph.proxy_config.defaults[0]
    for cfg in defaults.configs():
        print(cfg.keyword)
        assert cfg.keyword != test_keyword
    ph.add_timeout_tunnel()
    tunnel_found = False
    for cfg in defaults.configs():
        print(cfg.keyword)
        if cfg.keyword == test_keyword:
            tunnel_found = True
    assert tunnel_found


def test_get_config_names(ph, mock_remote_unit, config):
    """Test fetching backend names for related units."""
    config["group_id"] = "test_group"
    remote_unit, backend_name = ph.get_config_names([config])[0]
    assert remote_unit == "unit-mock-0-0"
    assert backend_name == "test_group"


def test_process_configs(ph, monkeypatch, config):
    """Test processing configuration."""
    # Test writting a config file
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    assert ph.process_configs([config])["cfg_good"] is True

    # Test writting two configs from one unit
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    assert ph.process_configs([config, config])["cfg_good"] is True

    # Error if tcp requested on existing http frontend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/1")
    config["mode"] = "tcp"
    assert ph.process_configs([config])["cfg_good"] is False

    # Successful tcp+tls on unused frontend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/2")
    config["external_port"] = 111
    config["mode"] = "tcp+tls"
    assert ph.process_configs([config])["cfg_good"] is True

    # Fail tcp+tls on existing tcp+tls frontend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/3")
    config["external_port"] = 111
    assert ph.process_configs([config])["cfg_good"] is False

    # Error if http requested on existing tcp frontend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/4")
    config["mode"] = "http"
    assert ph.process_configs([config])["cfg_good"] is False

    # Successful tcp on unused frontend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/1")
    config["external_port"] = 90
    config["mode"] = "tcp"
    assert ph.process_configs([config])["cfg_good"] is True

    # Fail tcp on existing tcp frontend
    config["external_port"] = 90
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/3")
    assert ph.process_configs([config])["cfg_good"] is False

    # Error if http requested on existing tcp frontend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/4")
    config["mode"] = "http"
    assert ph.process_configs([config])["cfg_good"] is False

    # Register with subdomain
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/2")
    config["subdomain"] = "subtest"
    config["external_port"] = 80
    assert ph.process_configs([config])["cfg_good"] is True

    # Register with only subdomain
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/3")
    config["urlbase"] = None
    assert ph.process_configs([config])["cfg_good"] is True

    # Add two units with a group-id
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/4")
    config["group_id"] = "test-group"
    assert ph.process_configs([config])["cfg_good"] is True
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/5")
    config["group_id"] = "test-group"
    assert ph.process_configs([config])["cfg_good"] is True

    # Add a unit with rewrite-path and local
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/6")
    config["group_id"] = "rewrite-group"
    config["rewrite-path"] = True
    config["acl-local"] = True
    config["urlbase"] = "/mock6"
    assert ph.process_configs([config])["cfg_good"] is True
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/7")
    assert ph.process_configs([config])["cfg_good"] is True
    backend = ph.get_backend("rewrite-group", create=False)
    rewrite_found = False
    for cfg in backend.configs():
        if cfg.keyword.startswith("http-request set-path"):
            rewrite_found = True
    assert rewrite_found
    assert backend.acl("local")
    check_found = False
    for server in backend.servers():
        for attribute in server.attributes:
            if "check" in attribute:
                check_found = True
    assert check_found

    # Add a unit with proxypass, ssl verify none, and no check
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/8")
    config["subdomain"] = False
    config["group_id"] = None
    config["rewrite-path"] = None
    config["acl-local"] = None
    config["urlbase"] = "/mock8"
    config["proxypass"] = True
    config["ssl"] = True
    config["ssl-verify"] = False
    config["external_port"] = 443
    config["check"] = False
    assert ph.process_configs([config])["cfg_good"] is True
    backend = ph.get_backend("unit-mock-8-0", create=False)
    forward_for_found = False
    for option in backend.options():
        if "forwardfor" in option.keyword:
            forward_for_found = True
    assert forward_for_found
    forward_proto_found = False
    for cfg in backend.configs():
        if "X-Forwarded-Proto https" in cfg.keyword:
            forward_proto_found = True
    assert forward_proto_found
    ssl_found = False
    for server in backend.servers():
        if "ssl verify none" in server.attributes:
            ssl_found = True
    assert ssl_found
    check_found = False
    for server in backend.servers():
        for attribute in server.attributes:
            if "check" in attribute:
                check_found = True
    assert not check_found

    # Check that the expected number of backends are in use
    # Backends 0-0,0-1,2,3,4,5,6,7 should be in use by HTTP port 80
    http_fe = ph.get_frontend(80, create=False)
    assert len(http_fe.usebackends()) == 8


def test_get_frontend(ph):
    """Test fetching the frontend."""
    import pyhaproxy

    assert ph.get_frontend(80, create=False) is None
    assert not isinstance(ph.get_frontend(80, create=False), pyhaproxy.config.Frontend)
    assert isinstance(ph.get_frontend(80), pyhaproxy.config.Frontend)
    assert isinstance(ph.get_frontend(80, create=False), pyhaproxy.config.Frontend)
    assert ph.get_frontend(70).port == "70"
    assert ph.get_frontend(80).port == "80"
    assert ph.get_frontend(90).port == "90"


def test_get_backend(ph, monkeypatch, config):
    """Test getting backends."""
    import pyhaproxy

    # Create and return a new backend
    new_be = ph.get_backend("test-backend")
    assert isinstance(new_be, pyhaproxy.config.Backend)
    assert new_be.name == "test-backend"
    assert new_be.configs() == []
    # Retrieve existing backend
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    ph.process_configs([config])
    backend = ph.get_backend("unit-mock-0-0")
    assert backend.name == "unit-mock-0-0"
    assert backend.configs() != []


def test_enable_stats(ph):
    """Test enabling stats."""
    # Can't enable if FE is in use
    fe9000 = ph.get_frontend(9000)
    assert fe9000.port == "9000"
    assert fe9000.name == "relation-9000"
    assert ph.enable_stats() is False
    # Can enable if FE is available
    fe9000.port = 0
    assert ph.enable_stats() is True
    festats = ph.get_frontend(9000)
    assert festats.name == "stats"


def test_disable_sats(ph):
    """Test disabling stats."""
    # 9k FE is Stats after enable
    assert ph.enable_stats() is True
    fe9000 = ph.get_frontend(9000)
    assert fe9000.name == "stats"
    # 9k FE is not Stats after disable
    ph.disable_stats()
    fe9000 = ph.get_frontend(9000)
    assert fe9000.name == "relation-9000"


def test_enable_redirect(ph):
    """Test enabling the HTTPS redirect."""
    ph.enable_redirect()
    fe80 = ph.get_frontend(80)
    assert fe80.port == "80"
    default = None
    for ub in fe80.usebackends():
        if ub.backend_name == "redirect":
            default = ub
    assert default is not None
    assert default.is_default is True
    be_redirect = ph.get_backend("redirect", create=False)
    assert be_redirect is not None


def test_disable_redirect(ph):
    """Test disabling the redirect."""
    # Enable redirect
    test_enable_redirect(ph)
    ph.disable_redirect()
    fe80 = ph.get_frontend(80, create=False)
    assert fe80 is None
    be_redirect = ph.get_backend("redirect", create=False)
    assert be_redirect is None


def test_available_for_http(ph, monkeypatch, config):
    """Test checking for HTTP backend."""
    # Create http at 80
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    assert ph.process_configs([config])["cfg_good"] is True
    fe80 = ph.get_frontend(80)
    # Create tcp at 90
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/1")
    config["mode"] = "tcp"
    config["external_port"] = 90
    assert ph.process_configs([config])["cfg_good"] is True
    fe90 = ph.get_frontend(90)
    # Get default stats frontend
    fe9000 = ph.get_frontend(9000)
    # Verify http checks
    assert ph.available_for_http(fe80) is True
    assert ph.available_for_http(fe90) is False
    # Check stats port
    assert ph.available_for_http(fe9000) is True
    fe9000.port = 0  # Move from 9k so stats can enable
    ph.enable_stats()
    fe9000 = ph.get_frontend(9000)
    assert ph.available_for_http(fe9000) is False


def test_available_for_tcp(ph, monkeypatch, config):
    """Test checking for a TCP backend."""
    # Create http at 80
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    assert ph.process_configs([config])["cfg_good"] is True
    fe80 = ph.get_frontend(80)
    # Create tcp at 90
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/1")
    config["mode"] = "tcp"
    config["external_port"] = 90
    assert ph.process_configs([config])["cfg_good"] is True
    fe90 = ph.get_frontend(90)
    # Get default stats frontend
    fe9000 = ph.get_frontend(9000)
    # Verify tcp checks
    assert ph.available_for_tcp(fe80, "unit-mock-0-0") is False
    assert ph.available_for_tcp(fe90, "unit-mock-0-0") is False
    assert ph.available_for_tcp(fe90, "unit-mock-1-0") is True
    # Check stats port
    assert ph.available_for_tcp(fe9000, "unit-mock-0-0") is True
    assert ph.available_for_tcp(fe9000, "unit-mock-1-0") is True
    fe9000.port = 0  # Move from 9k so stats can enable
    ph.enable_stats()
    fe9000 = ph.get_frontend(9000)
    assert ph.available_for_tcp(fe9000, "unit-mock-0-0") is False
    assert ph.available_for_tcp(fe9000, "unit-mock-1-0") is False


def test_clean_config(ph, monkeypatch, config):
    """Test cleaning the config."""
    # Test adding and removing single unit
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    remote_unit, backend_name = ph.get_config_names([config])[0]
    ph.process_configs([config])
    assert ph.get_frontend(80, create=False) is not None
    ph.clean_config(remote_unit, backend_name)
    assert ph.get_frontend(80, create=False) is None
    # Setup mulpitle units to test with
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    assert ph.process_configs([config])["cfg_good"] is True
    unit_0, backend_0 = ph.get_config_names([config])[0]
    ph.process_configs([config])

    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/1")
    unit_1, backend_1 = ph.get_config_names([config])[0]
    ph.process_configs([config])

    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/2")
    config["group_id"] = "test-group"
    unit_2, backend_2 = ph.get_config_names([config])[0]
    ph.process_configs([config])

    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/3")
    unit_3, backend_3 = ph.get_config_names([config])[0]
    ph.process_configs([config])
    assert backend_2 == backend_3

    assert ph.get_frontend(80, create=False) is not None
    fe = ph.get_frontend(80, create=False)
    assert len(fe.usebackends()) == 4
    assert len(fe.acls()) == 8
    assert ph.get_backend(backend_0, create=False) is not None
    assert ph.get_backend(backend_1, create=False) is not None
    assert ph.get_backend(backend_2, create=False) is not None
    assert ph.get_backend(backend_3, create=False) is not None

    # Remove 1 of the grouped backends and re-check
    ph.clean_config(unit_3, backend_3)
    assert len(fe.usebackends()) == 3
    assert len(fe.acls()) == 6
    assert ph.get_backend(backend_0, create=False) is not None
    assert ph.get_backend(backend_1, create=False) is not None
    assert ph.get_backend(backend_2, create=False) is not None
    assert ph.get_backend(backend_3, create=False) is not None

    # Remove the other and check that the group is now gone
    ph.clean_config(unit_2, backend_2)
    assert len(fe.usebackends()) == 2
    assert len(fe.acls()) == 4
    assert ph.get_backend(backend_0, create=False) is not None
    assert ph.get_backend(backend_1, create=False) is not None
    assert ph.get_backend(backend_2, create=False) is None
    assert ph.get_backend(backend_3, create=False) is None

    # Remove another backend
    ph.clean_config(unit_1, backend_1)
    assert len(fe.usebackends()) == 1
    assert len(fe.acls()) == 2
    assert ph.get_backend(backend_0, create=False) is not None
    assert ph.get_backend(backend_1, create=False) is None
    assert ph.get_backend(backend_2, create=False) is None
    assert ph.get_backend(backend_3, create=False) is None

    # Remove final backend and frontend
    ph.clean_config(unit_0, backend_0)
    assert ph.get_backend(backend_0, create=False) is None
    assert ph.get_backend(backend_1, create=False) is None
    assert ph.get_backend(backend_2, create=False) is None
    assert ph.get_backend(backend_3, create=False) is None


def test_save_config(ph, monkeypatch, config):
    """Test saving the config."""
    import os

    initial_time = os.path.getmtime(ph.proxy_config_file)
    # Modify config should change mtime
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    ph.process_configs([config])
    time2 = os.path.getmtime(ph.proxy_config_file)
    assert initial_time != time2


def test_update_ports(ph, monkeypatch, config):
    """Test updating opened ports."""
    import sys

    mports = sys.modules["libhaproxy"].subprocess.check_output
    # Check that ports start empty and dont' change on update_ports
    assert mports.open_ports == ""
    ph.update_ports()
    assert mports.open_ports == ""
    # Ading a port opens it
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    unit_0, backend_0 = ph.get_config_names([config])[0]
    ph.process_configs([config])
    ph.update_ports()
    assert mports.open_ports == "80/tcp\n"
    # Duplicate ports aren't added
    ph.get_frontend(80)
    ph.update_ports()
    assert mports.open_ports == "80/tcp\n"
    # If ports are removed, they get added back
    mports.open_ports = ""
    ph.update_ports()
    assert mports.open_ports == "80/tcp\n"
    # If a frontend is removed, so is the port
    ph.clean_config(unit_0, backend_0)
    assert mports.open_ports == ""
    # Close stats port if open during update
    ph.charm_config["enable-stats"] = True
    ph.enable_stats()
    assert mports.open_ports == ""
    print(mports.open_ports)
    ph.update_ports()
    print(mports.open_ports)
    assert mports.open_ports == ""


def test_merge_letsencrypt_cert(ph, cert):
    """Test merging certbot scripts."""
    assert not os.path.isfile(ph.cert_file)
    ph.merge_letsencrypt_cert()
    assert os.path.isfile(ph.cert_file)
    with open(ph.cert_file, "r") as cert_file:
        assert cert_file.readline() == "fullchain.pem\n"
        assert cert_file.readline() == "privkey.pem\n"


def test_add_cron(ph, mock_crontab):
    """Test adding cron jobs."""
    action = "test-action"
    interval = "test-interval"
    # Collect CronTab calls from add and remove
    ph.add_cron(action, interval)
    ph.remove_cron(action)
    calls = {}
    for call in mock_crontab.mock_calls:
        name, args, kwargs = call
        calls[name] = {"args": args, "kwargs": kwargs}

    # Check add cron calls CronTab with expected action and interval
    assert calls["().new"]["kwargs"]["command"].split("/")[-1] == action
    assert interval in calls["().new().setall"]["args"]
    # Check that add and remove use same comment
    assert calls["().new"]["kwargs"]["comment"] == calls["().find_comment"]["args"][0]


def test_cert_cron(ph, mock_crontab):
    """Test adding the certificate renewal cron job."""
    action = "renew-cert"
    interval = "@daily"
    ph.add_cert_cron()
    ph.remove_cert_cron()
    calls = {}
    for call in mock_crontab.mock_calls:
        name, args, kwargs = call
        calls[name] = {"args": args, "kwargs": kwargs}

    # Check add cron calls CronTab with expected action and interval
    assert calls["().new"]["kwargs"]["command"].split("/")[-1] == action
    assert interval in calls["().new().setall"]["args"]
    # Check that add and remove use same comment
    assert calls["().new"]["kwargs"]["comment"] == calls["().find_comment"]["args"][0]


def test_upnp_cron(ph, mock_crontab):
    """Test upnp renewal cron job."""
    action = "renew-upnp"
    interval = "@hourly"
    ph.add_upnp_cron()
    ph.remove_upnp_cron()
    calls = {}
    for call in mock_crontab.mock_calls:
        name, args, kwargs = call
        calls[name] = {"args": args, "kwargs": kwargs}

    # Check add cron calls CronTab with expected action and interval
    assert calls["().new"]["kwargs"]["command"].split("/")[-1] == action
    assert interval in calls["().new().setall"]["args"]
    # Check that add and remove use same comment
    assert calls["().new"]["kwargs"]["comment"] == calls["().find_comment"]["args"][0]


def test_enable_letsencrypt(ph, cert, mock_crontab):
    """Test enabling certbot."""
    ph.charm_config["enable-letsencrypt"] = True
    ph.enable_letsencrypt()
    fe80 = ph.get_frontend(80, create=False)
    fe443 = ph.get_frontend(443, create=False)
    fe111 = ph.get_frontend(111, tls=True)
    fe90 = ph.get_frontend(90)
    # assert fe80.config_block['acls'][0].name == 'letsencrypt'
    assert fe80.usebackend("letsencrypt-backend")
    assert "mock.pem" in fe443.binds()[0].attributes[0]
    assert len(fe80.binds()[0].attributes) == 0
    assert "mock.pem" in fe111.binds()[0].attributes[0]
    assert len(fe90.binds()[0].attributes) == 0
    assert fe443.acl("letsencrypt")
    assert fe443.usebackend("letsencrypt-backend")
    assert fe443.config("reqirep", "Destination:\\ https(.*) Destination:\\ http\\\\1 ")
    # assert 'reqirep' in fe443.config_block['configs'][0][0]


def test_disable_letsencrypt(ph, cert, mock_crontab, monkeypatch, config):
    """Test disabling certbot."""
    fe90 = ph.get_frontend(90)
    fe111 = ph.get_frontend(111, tls=True)
    # Remove letsencrypt and all unused sections
    ph.charm_config["enable-letsencrypt"] = True
    ph.enable_letsencrypt()
    assert ph.get_frontend(80, create=False) is not None
    assert ph.get_frontend(443, create=False) is not None
    assert ph.get_backend("letsencrypt-backend", create=False) is not None
    ph.charm_config["enable-letsencrypt"] = False
    ph.disable_letsencrypt()
    assert ph.get_frontend(80, create=False) is None
    assert ph.get_frontend(443, create=False) is None
    assert ph.get_backend("letsencrypt-backend", create=False) is None

    # Remove letsencrypt but not other frontends
    ph.charm_config["enable-letsencrypt"] = True
    ph.enable_letsencrypt()
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/0")
    ph.process_configs([config])
    monkeypatch.setattr("libhaproxy.hookenv.remote_unit", lambda: "unit-mock/1")
    config["external_port"] = 443
    ph.process_configs([config])
    ph.charm_config["enable-letsencrypt"] = False
    ph.disable_letsencrypt()
    fe80 = ph.get_frontend(80, create=False)
    fe443 = ph.get_frontend(443, create=False)
    assert fe80.acl("unit-mock-0-0")
    assert fe80.usebackend("unit-mock-0-0")
    assert fe111.binds()[0].attributes == []
    assert fe90.binds()[0].attributes == []
    assert fe443.binds()[0].attributes == []
    assert fe443.acl("unit-mock-1-0")
    assert fe443.usebackend("unit-mock-1-0")
    assert fe443.configs() == []
    assert ph.get_backend("letsencrypt-backend", create=False) is None


def test_renew_cert(ph, monkeypatch):
    """Test renewing certificates."""
    import mock

    mocks = {
        "disable": mock.Mock(),
        "enable": mock.Mock(),
        "renew": mock.Mock(),
        "merge": mock.Mock(),
    }
    monkeypatch.setattr(ph, "disable_letsencrypt", mocks["disable"])
    monkeypatch.setattr(ph, "enable_letsencrypt", mocks["enable"])
    monkeypatch.setattr("libhaproxy.letsencrypt.renew", mocks["renew"])
    monkeypatch.setattr(ph, "merge_letsencrypt_cert", mocks["merge"])
    assert mocks["disable"].call_count == 0
    assert mocks["enable"].call_count == 0
    assert mocks["renew"].call_count == 0
    assert mocks["merge"].call_count == 0
    ph.renew_cert()
    assert mocks["disable"].call_count == 1
    assert mocks["enable"].call_count == 1
    assert mocks["renew"].call_count == 0
    assert mocks["merge"].call_count == 0
    ph.renew_cert(full=False)
    assert mocks["disable"].call_count == 1
    assert mocks["enable"].call_count == 1
    assert mocks["renew"].call_count == 1
    assert mocks["merge"].call_count == 1


def test_renew_upnp(ph):
    """Test renewing upnp port forwards."""
    import mock

    with mock.patch("libhaproxy.subprocess.check_call") as mockports:
        ph.renew_upnp()
        assert mockports.call_count == 0
    ph.get_frontend(80)
    ph.get_frontend(90)
    ph.update_ports()
    with mock.patch("libhaproxy.subprocess.check_call") as mockports:
        ph.renew_upnp()
        assert mockports.call_count == 2
    ph.get_frontend(8080)
    ph.update_ports()
    with mock.patch("libhaproxy.subprocess.check_call") as mockports:
        ph.renew_upnp()
        assert mockports.call_count == 3


def test_release_upnp(ph):
    """Test releasing the upnp port forward."""
    import mock

    with mock.patch("libhaproxy.subprocess.check_call") as mockports:
        ph.release_upnp()
        assert mockports.call_count == 0
    ph.get_frontend(80)
    ph.get_frontend(90)
    ph.update_ports()
    with mock.patch("libhaproxy.subprocess.check_call") as mockports:
        ph.release_upnp()
        assert mockports.call_count == 2
    ph.get_frontend(8080)
    ph.update_ports()
    with mock.patch("libhaproxy.subprocess.check_call") as mockports:
        ph.release_upnp()
        assert mockports.call_count == 3
