from charms.reactive import hook, when, when_all, when_any, when_not, set_state
from charmhelpers.core import hookenv, host
from charmhelpers import fetch

# import subprocess
import fileinput
import os
import errno

from libhaproxy import ProxyHelper

ph = ProxyHelper()


@when_not('haproxy.installed')
def install_haproxy():
    hookenv.status_set('maintenance', 'Installing HAProxy')
    fetch.add_source(ph.ppa)
    fetch.apt_update()
    fetch.install('haproxy')
    set_state('haproxy.installed')


@when('haproxy.installed')
@when_not('haproxy.configured')
def configure_haproxy():
    hookenv.status_set('maintenance', 'Configuring HAProxy')
    try:
        os.makedirs(ph.ssl_path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise
    # Enable udp for rsyslog
    for line in fileinput.input('/etc/rsyslog.conf', inplace=True):
        line = line.replace('#module(load="imudp")', 'module(load="imudp")')
        line = line.replace('#input(type="imudp" port="514")', 'input(type="imudp" port="514")')
        print(line, end='')  # end statement to avoid inserting new lines at the end of the line
    host.service_restart('rsyslog.service')
    if ph.charm_config['enable-stats']:
        ph.enable_stats()
    if ph.charm_config['enable-letsencrypt']:
        ph.enable_letsencrypt()
    if ph.charm_config['enable-upnp']:
        ph.add_upnp_cron()
    if ph.charm_config['enable-https-redirect']:
        ph.enable_redirect()
    ph.add_timeout_tunnel()
    hookenv.status_set('active', '')
    set_state('haproxy.configured')


@when_all('reverseproxy.triggered', 'reverseproxy.changed')
def configure_relation(reverseproxy, *args):
    hookenv.status_set('maintenance', 'Setting up relation')
    hookenv.log("Received config: {}".format(reverseproxy.config), "Info")
    status = ph.process_config(reverseproxy.config)
    reverseproxy.set_cfg_status(**status)
    hookenv.status_set('active', '')


@when_all('reverseproxy.triggered', 'reverseproxy.departed')
def remove_relation(reverseproxy, *args):
    hookenv.log("Removing config for: {}".format(hookenv.remote_unit()))
    unit_name, backend_name = ph.get_config_names(reverseproxy.config)
    ph.clean_config(unit=unit_name, backend_name=backend_name)


@when('config.changed.version')
def version_changed():
    if hookenv.hook_name() == "install":
        return
    hookenv.log('Version change will not affect running units', 'WARNING')
    hookenv.status_set('active', "version change to {} not applied, redeploy "
                       "unit for version change".format(ph.charm_config['version']))


@when_any('config.changed.enable-stats',
          'config.changed.stats-user',
          'config.changed.stats-passwd',
          'config.changed.stats-url',
          'config.changed.stats-port',
          'config.changed.stats-local')
def stats_changed():
    if hookenv.hook_name() == "install":
        return
    if ph.charm_config['enable-stats']:
        hookenv.log('Enabling stats for config change')
        ph.enable_stats()
    else:
        hookenv.log('Disabling stats for config change')
        ph.disable_stats()


@when_any('config.changed.enable-upnp')
def upnp_changed():
    if hookenv.hook_name() == "install":
        return
    if ph.charm_config['enable-upnp']:
        ph.add_upnp_cron()
        ph.renew_upnp()
    else:
        ph.remove_upnp_cron()
        # Turning on upnp to close ports so a release is issued
        ph.charm_config['enable-upnp'] = True
        ph.release_upnp()
        # Turning upnp back off and opening ports w/o upnp
        ph.charm_config['enable-upnp'] = False
        ph.update_ports()


@when('config.changed.upnp-renew-interval')
def upnp_interval_changed():
    if hookenv.hook_name() == "install":
        return
    ph.remove_upnp_cron()
    if ph.charm_config['enable-upnp']:
        ph.add_upnp_cron()


@when_any('config.changed.enable-letsencrypt',
          'config.changed.letsencrypt-domains',
          'config.changed.letsencrypt-email')
def letsencrypt_config_changed():
    if hookenv.hook_name() == "install":
        return
    ph.disable_letsencrypt()
    if ph.charm_config['enable-letsencrypt']:
        ph.enable_letsencrypt()


@when('config.changed.cert-renew-interval')
def cert_interval_changed():
    if hookenv.hook_name() == "install":
        return
    ph.remove_cert_cron()
    if ph.charm_config['enable-letsencrypt']:
        ph.add_cert_cron()


@when('config.changed.enable-https-redirect')
def redirect_changed():
    if hookenv.hook_name() == "install":
        return
    if ph.charm_config['enable-https-redirect']:
        ph.enable_redirect()
    else:
        ph.disable_redirect()


@hook('stop')
def stop_haproxy():
    if ph.charm_config['enable-stats']:
        hookenv.log("Disabling status to free any opened ports", "INFO")
        ph.disable_stats()
        hookenv.log("Disabling letsencrypt to free any opened ports", "INFO")
        ph.disable_letsencrypt()
