import mock
import imp


class TestActions():
    def test_renew_cert(self, ph, monkeypatch):
        mocks = {'disable': mock.Mock(), 'enable': mock.Mock(), 'renew':
                 mock.Mock(), 'merge': mock.Mock()}
        monkeypatch.setattr(ph, 'disable_letsencrypt', mocks['disable'])
        monkeypatch.setattr(ph, 'enable_letsencrypt', mocks['enable'])
        monkeypatch.setattr('libhaproxy.letsencrypt.renew', mocks['renew'])
        monkeypatch.setattr(ph, 'merge_letsencrypt_cert', mocks['merge'])
        # Verify call counts
        assert mocks['disable'].call_count == 0
        assert mocks['enable'].call_count == 0
        assert mocks['renew'].call_count == 0
        assert mocks['merge'].call_count == 0
        # Test a calling with full=True
        monkeypatch.setattr('libhaproxy.hookenv.action_get', lambda x: True)
        imp.load_source('renew_cert', './actions/renew-cert')
        assert mocks['disable'].call_count == 1
        assert mocks['enable'].call_count == 1
        assert mocks['renew'].call_count == 0
        assert mocks['merge'].call_count == 0
        # Test calling with full=False
        monkeypatch.setattr('libhaproxy.hookenv.action_get', lambda x: False)
        imp.load_source('renew_cert', './actions/renew-cert')
        assert mocks['disable'].call_count == 1
        assert mocks['enable'].call_count == 1
        assert mocks['renew'].call_count == 1
        assert mocks['merge'].call_count == 1
        # Test exception which juju-run will cause
        monkeypatch.setattr('libhaproxy.hookenv.action_get', lambda x: 1 / 0)
        imp.load_source('renew_cert', './actions/renew-cert')
        assert mocks['disable'].call_count == 1
        assert mocks['enable'].call_count == 1
        assert mocks['renew'].call_count == 2
        assert mocks['merge'].call_count == 2

    def test_renew_upnp(self, ph, monkeypatch):
        mock_renew = mock.Mock()
        monkeypatch.setattr(ph, 'renew_upnp', mock_renew)
        assert mock_renew.call_count == 0
        imp.load_source('renew_upnp', './actions/renew-upnp')
        assert mock_renew.call_count == 1
