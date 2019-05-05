import os
import pytest
import requests
import subprocess
import time

# Treat tests as coroutines
pytestmark = pytest.mark.asyncio

juju_repository = os.getenv('JUJU_REPOSITORY', '.').rstrip('/')
series = ['xenial',
          pytest.param('bionic', marks=pytest.mark.xfail(reason='canary')),
          pytest.param('cosmic', marks=pytest.mark.xfail(reason='canary')),
          ]
sources = [('local', '{}/builds/haproxy'.format(juju_repository)),
           ('jujucharms', 'cs:~pirate-charmers/haproxy')]
juju_repository = os.getenv('JUJU_REPOSITORY', '.').rstrip('/')


# Custom fixtures
@pytest.fixture(params=series)
def series(request):
    return request.param


@pytest.fixture(params=sources, ids=[s[0] for s in sources])
def source(request):
    return request.param


@pytest.fixture
async def app(model, series, source):
    app_name = 'haproxy-{}-{}'.format(series, source[0])
    return await model._wait_for_new('application', app_name)


async def test_haproxy_deploy(model, series, source, request):
    # Starts a deploy for each series
    # Using subprocess b/c libjuju fails with JAAS
    # https://github.com/juju/python-libjuju/issues/221
    application_name = 'haproxy-{}-{}'.format(series, source[0])
    cmd = ['juju', 'deploy', source[1], '-m', model.info.name,
           '--series', series, application_name]
    if request.node.get_closest_marker('xfail'):
        cmd.append('--force')
    subprocess.check_call(cmd)


async def test_charm_upgrade(model, app):
    if app.name.endswith('local'):
        pytest.skip("No need to upgrade the local deploy")
    unit = app.units[0]
    await model.block_until(lambda: unit.agent_status == 'idle')
    subprocess.check_call(['juju',
                           'upgrade-charm',
                           '--switch={}'.format(sources[0][1]),
                           '-m', model.info.name,
                           app.name,
                           ])
    await model.block_until(lambda: unit.agent_status == 'executing')


async def test_haproxy_status(app, model):
    await model.block_until(lambda: app.status == 'active')
    assert True


async def test_wrong_login(app):
    unit = app.units[0]
    page = requests.get('http://{}:{}/{}'.format(unit.public_address, 9000, 'ha-stats'),
                        auth=requests.auth.HTTPBasicAuth('admin', 'fail')
                        )
    assert page.status_code == 401


async def test_disable_stats(model, app):
    unit = app.units[0]
    await app.set_config({'enable-stats': 'False'})
    time.sleep(2)
    await model.block_until(lambda: app.status == 'active')

    with pytest.raises(requests.exceptions.ConnectionError):
        page = requests.get('http://{}:{}/{}'.format(unit.public_address, 9000, 'ha-stats'),
                            auth=requests.auth.HTTPBasicAuth('admin', 'admin'),
                            headers={'Cache-Control': 'no-cache'}
                            )
        print(page.json)


async def test_action_renew_upnp(app):
    unit = app.units[0]
    action = await unit.run_action('renew-upnp')
    action = await action.wait()
    assert action.status == 'completed'


async def test_action_renew_cert(app):
    unit = app.units[0]
    action = await unit.run_action('renew-cert')
    action = await action.wait()
    assert action.status == 'completed'
