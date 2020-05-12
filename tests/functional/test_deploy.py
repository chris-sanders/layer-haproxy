"""Functional testing for the haproxy charm."""
import os
import pytest
import requests
import subprocess
import time

# from juju.model import Model

# Treat tests as coroutines
pytestmark = pytest.mark.asyncio

juju_repository = os.getenv("JUJU_REPOSITORY", ".").rstrip("/")
series = ["xenial", pytest.param("bionic", marks=pytest.mark.xfail(reason="canary"))]
sources = [
    ("local", "{}/builds/haproxy".format(juju_repository)),
    ("jujucharms", "cs:~pirate-charmers/haproxy"),
]


# Uncomment for re-using the current model, useful for debugging functional tests
# @pytest.fixture(scope='module')
# async def model():
#     from juju.model import Model
#     model = Model()
#     await model.connect_current()
#     yield model
#     await model.disconnect()


# Custom fixtures
@pytest.fixture(params=series)
def series(request):
    """Fixture for accessing the series under test."""
    return request.param


@pytest.fixture(params=sources, ids=[s[0] for s in sources])
def source(request):
    """Fixture for accessing the source under test."""
    return request.param


@pytest.fixture
async def app(model, series, source):
    """Fixture for accessing the application instance under test."""
    app_name = "haproxy-{}-{}".format(series, source[0])
    return await model._wait_for_new("application", app_name)


@pytest.fixture()
async def nostats(app):
    """Fixture for toggling the stats endpoint."""
    print("Disabling stats")
    await app.set_config({"enable-stats": "False"})
    time.sleep(10)
    yield
    print("Re-enabling stats")
    await app.set_config({"enable-stats": "True"})
    time.sleep(5)


async def test_haproxy_deploy(model, series, source, request):
    """Test the deployment of haproxy for supported and canary series."""
    # Starts a deploy for each series
    # Using subprocess b/c libjuju fails with JAAS
    # https://github.com/juju/python-libjuju/issues/221
    application_name = "haproxy-{}-{}".format(series, source[0])
    cmd = [
        "juju",
        "deploy",
        source[1],
        "-m",
        model.info.name,
        "--series",
        series,
        application_name,
    ]
    if request.node.get_closest_marker("xfail"):
        # If series is 'xfail' force install to allow testing against versions not in
        # metadata.yaml
        cmd.append("--force")
    subprocess.check_call(cmd)


async def test_charm_upgrade(model, app):
    """Upgrade local charm from the charmstore versions for each series."""
    if app.name.endswith("local"):
        pytest.skip("No need to upgrade the local deploy")
    unit = app.units[0]
    # check if version is on the charm store
    if app.status == 'error':
        pytest.skip("Not possible to upgrade errored canary versions")
    await model.block_until(lambda: unit.agent_status == "idle")
    subprocess.check_call(
        [
            "juju",
            "upgrade-charm",
            "--switch={}".format(sources[0][1]),
            "-m",
            model.info.name,
            app.name,
        ]
    )
    await model.block_until(lambda: unit.agent_status == "executing")


# Tests
async def test_haproxy_status(model, app):
    """Verify status for all deployed series."""
    await model.block_until(lambda: app.status == "active")
    unit = app.units[0]
    await model.block_until(lambda: unit.agent_status == "idle")


async def test_wrong_login(app):
    """Test that the admin endpoint correctly returns 401 unauthorised."""
    unit = app.units[0]
    page = requests.get(
        "http://{}:{}/{}".format(unit.public_address, 9000, "ha-stats"),
        auth=requests.auth.HTTPBasicAuth("admin", "fail"),
    )
    assert page.status_code == 401


@pytest.mark.usefixtures("nostats")
async def test_disable_stats(app):
    """Test that the connection fails when stats are disabled."""
    unit = app.units[0]
    # Disable stats prevents connection
    with pytest.raises(requests.exceptions.ConnectionError):
        page = requests.get(
            "http://{}:{}/{}".format(unit.public_address, 9000, "ha-stats"),
            auth=requests.auth.HTTPBasicAuth("admin", "admin"),
            headers={"Cache-Control": "no-cache"},
        )
        print(page.json)


async def test_action_renew_upnp(app):
    """Test renewal of upnp port forward."""
    unit = app.units[0]
    action = await unit.run_action("renew-upnp")
    action = await action.wait()
    assert action.status == "completed"


async def test_action_renew_cert(app):
    """Test renewing certificates via certbot."""
    unit = app.units[0]
    action = await unit.run_action("renew-cert")
    action = await action.wait()
    assert action.status == "completed"
