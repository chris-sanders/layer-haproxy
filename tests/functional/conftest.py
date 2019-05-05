#!/usr/bin/python3
'''
Reusable pytest fixtures for functional testing

Environment variables
---------------------

test_preserve_model:
if set, the testing model won't be torn down at the end of the testing session
'''

import asyncio
import os
import uuid
import pytest
import subprocess

from juju.controller import Controller
from juju_tools import JujuTools


@pytest.fixture(scope='module')
def event_loop():
    '''Override the default pytest event loop to allow for fixtures using a
    broader scope'''
    loop = asyncio.get_event_loop_policy().new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_debug(True)
    yield loop
    loop.close()
    asyncio.set_event_loop(None)


@pytest.fixture(scope='module')
async def controller():
    '''Connect to the current controller'''
    _controller = Controller()
    await _controller.connect_current()
    yield _controller
    await _controller.disconnect()


@pytest.fixture(scope='module')
async def model(controller):
    '''This model lives only for the duration of the test'''
    model_name = "functest-{}".format(str(uuid.uuid4())[-12:])
    _model = await controller.add_model(model_name,
                                        cloud_name=os.getenv('PYTEST_CLOUD_NAME'),
                                        region=os.getenv('PYTEST_CLOUD_REGION'),
                                        )
    # https://github.com/juju/python-libjuju/issues/267
    subprocess.check_call(['juju', 'models'])
    while model_name not in await controller.list_models():
        await asyncio.sleep(1)
    yield _model
    await _model.disconnect()
    if not os.getenv('PYTEST_KEEP_MODEL'):
        await controller.destroy_model(model_name)
        while model_name in await controller.list_models():
            await asyncio.sleep(1)


@pytest.fixture(scope='module')
async def jujutools(controller, model):
    tools = JujuTools(controller, model)
    return tools
