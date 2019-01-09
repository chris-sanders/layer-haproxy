from charmhelpers.core import hookenv, host

from charms import layer
from pyhaproxy.parse import Parser
from pyhaproxy.render import Render
from crontab import CronTab

import pyhaproxy.config as Config
import reactive.letsencrypt as letsencrypt
import subprocess


class ProxyHelper():
    def __init__(self):
        self.charm_config = hookenv.config()
        self.letsencrypt_config = layer.options('letsencrypt')
        self.ppa = "ppa:vbernat/haproxy-{}".format(self.charm_config['version'])
        self.proxy_config_file = "/etc/haproxy/haproxy.cfg"
        self._proxy_config = None
        self.domain_name = self.charm_config['letsencrypt-domains'].split(',')[0]
        self.ssl_path = '/etc/haproxy/ssl/'
        self.cert_file = self.ssl_path + self.domain_name + '.pem'

    @property
    def proxy_config(self):
        if not self._proxy_config:
            self._proxy_config = Parser(self.proxy_config_file).build_configuration()
        return self._proxy_config

    def add_timeout_tunnel(self, timeout='1h', save=True):
        tunnel_config = Config.Config("timeout tunnel", "{}".format(timeout))
        defaults = self.proxy_config.defaults[0]
        for cfg in defaults.configs():
            if cfg.keyword == 'timeout tunnel':
                defaults.remove_config(cfg)
        defaults.add_config(tunnel_config)
        if save:
            self.save_config()

    def get_config_names(self, config):
        ''' Note this requires a remote unit '''
        remote_unit = hookenv.remote_unit().replace('/', '-')
        backend_name = config['group_id'] or remote_unit
        return remote_unit, backend_name

    def process_config(self, config):
        ''' Note this requires a remote unit '''
        remote_unit, backend_name = self.get_config_names(config)

        # Remove any prior configuration as it might have changed, do not write cfg file we still have edits to make
        self.clean_config(unit=remote_unit, backend_name=backend_name, save=False)

        # Get the frontend, create if not present
        frontend = self.get_frontend(config['external_port'])

        # urlbase use to accept / now they are added automatically
        # to avoid errors strip it from old configs
        if config['urlbase']:
            config['urlbase'] = config['urlbase'].strip('/')

        if config['mode'] == 'http':
            if not self.available_for_http(frontend):
                return({"cfg_good": False, "msg": "Port not available for http routing"})

            # Add ACL's to the frontend
            if config['urlbase']:
                acl = Config.Acl(name=remote_unit, value='path_beg /{}/'.format(config['urlbase']))
                frontend.add_acl(acl)
                acl = Config.Acl(name=remote_unit, value='path /{}'.format(config['urlbase']))
                frontend.add_acl(acl)
            if config['subdomain']:
                acl = Config.Acl(name=remote_unit, value='hdr_beg(host) -i {}'.format(config['subdomain']))
                frontend.add_acl(acl)
            # Add use_backend section to the frontend
            use_backend = Config.UseBackend(backend_name=backend_name,
                                            operator='if',
                                            backend_condition=remote_unit,
                                            is_default=False)
            frontend.add_usebackend(use_backend)
        if config['mode'] == 'tcp':
            if not self.available_for_tcp(frontend, backend_name):
                return({"cfg_good": False, "msg": "Frontend already in use, can not set up tcp mode"})

            mode_config = Config.Config('mode tcp', '')
            frontend.add_config(mode_config)

            use_backend = Config.UseBackend(backend_name=backend_name,
                                            operator='',
                                            backend_condition='',
                                            is_default=True)
            frontend.add_usebackend(use_backend)

        # Get the backend, create if not present
        backend = self.get_backend(backend_name)

        # Add server to the backend
        if config['mode'] == 'http':
            # Add cookie config if not already present
            cookie_found = False
            cookie = 'cookie SERVERID insert indirect nocache'
            for test_config in backend.configs():
                if cookie in test_config.keyword:
                    cookie_found = True
            if not cookie_found:
                backend.add_config(Config.Config(cookie, ''))
            attributes = ['cookie {}'.format(remote_unit)]
            # Add httpchk option if not present
            if config['group_id']:
                httpchk_found = False
                httpchk = 'httpchk GET {} HTTP/1.0'.format(config['urlbase'] or '/')
                for test_option in backend.options():
                    if httpchk in test_option.keyword:
                        httpchk_found = True
                if not httpchk_found:
                    backend.add_option(Config.Option(httpchk, ''))
                attributes.append('check')
            # Add rewrite-path if requested and not present
            if config['rewrite-path'] and config['urlbase']:
                rewrite_found = False
                rewrite = 'http-request set-path %[path,regsub(^/{}/?,/)]'.format(config['urlbase'])
                for test_cfg in backend.configs():
                    if rewrite in test_cfg.keyword:
                        rewrite_found = True
                if not rewrite_found:
                    backend.add_config(Config.Config(rewrite, ''))
            if config['acl-local']:
                if not backend.acl('local'):
                    backend.add_acl(Config.Acl('local', 'src 10.0.0.0/8 192.168.0.0/16 127.0.0.0/8'))
                    backend.add_config(Config.Config('http-request deny if !local', ''))
            if config['proxypass']:
                proxy_found = False
                for test_option in backend.options():
                    if 'forwardfor' in test_cfg.keyword:
                        proxy_found = True
                if not proxy_found:
                    backend.add_option(Config.Option('forwardfor', ''))
                if config['external_port'] == 443:
                    forward_for = 'http-request set-header X-Forwarded-Proto https'
                else:
                    forward_for = 'http-request set-header X-Forwarded-Proto http'
                backend.add_config(Config.Config(forward_for, ''))
            if config['ssl']:
                if config['ssl-verify']:
                    ssl_attrib = 'ssl'
                else:
                    ssl_attrib = 'ssl verify none'
                attributes.append(ssl_attrib)
        else:
            attributes = ['']
        server = Config.Server(name=remote_unit, host=config['internal_host'], port=config['internal_port'], attributes=attributes)
        backend.add_server(server)

        # Render new cfg file
        self.save_config()
        return({"cfg_good": True, "msg": "configuration applied"})

    def available_for_http(self, frontend):
        if frontend.name == "stats":
            return False
        for config in frontend.configs():
            if "mode tcp" in config.keyword:
                return False
        return True

    def available_for_tcp(self, frontend, backend_name):
        if len(frontend.acls()):
            return False
        if len(frontend.usebackends()):
            valid_backend = False
            for ub in frontend.usebackends():
                if backend_name == ub.backend_name:
                    valid_backend = True
            if not valid_backend:
                return False
        return True

    def enable_stats(self, save=True):
        # Remove any previous stats
        self.disable_stats(save=False)

        # Check that no frontend exists with conflicting port
        if self.get_frontend(port=self.charm_config['stats-port'], create=False) is not None:
            hookenv.log("Stats port {} already in use".format(self.charm_config['stats-port']), 'ERROR')
            if save:
                self.save_config()
            return False

        # Generate new front end for stats
        user_string = '{}:{}'.format(self.charm_config['stats-user'], self.charm_config['stats-passwd'])
        config_block = []
        config_block.append(Config.Bind('0.0.0.0', self.charm_config['stats-port'], None))
        config_block.append(Config.Config('stats enable', ''))
        config_block.append(Config.Config('stats auth {}'.format(user_string), ''))
        config_block.append(Config.Config('stats uri {}'.format(self.charm_config['stats-url']),
                                          ''))
        if self.charm_config['stats-local']:
            config_block.append(Config.Acl('local', 'src 10.0.0.0/8 192.168.0.0/16 127.0.0.0/8'))
            config_block.append(Config.Config('http-request deny if !local', ''))
        frontend = Config.Frontend('stats', '0.0.0.0', str(self.charm_config['stats-port']), config_block)
        self.proxy_config.frontends.append(frontend)
        if save:
            self.save_config()
        return True

    def disable_stats(self, save=True):
        # Remove any previous stats frontend
        self.proxy_config.frontends[:] = [fe for fe in self.proxy_config.frontends if fe.name != 'stats']
        if save:
            self.save_config()

    def enable_redirect(self, save=True):
        backend_name = 'redirect'

        # remove any prevoius configureation
        self.disable_redirect(save=False)

        # Get or create frontend 80
        frontend = self.get_frontend(port=80)

        # Add use_backend section to the frontend
        use_backend = Config.UseBackend(backend_name=backend_name,
                                        operator='',
                                        backend_condition='',
                                        is_default=True)
        frontend.add_usebackend(use_backend)

        # Get the backend, create if not present
        backend = self.get_backend(backend_name)

        # Add redirect option to the backend
        redirect_config = Config.Config('redirect scheme https', '')
        backend.add_config(redirect_config)

        # Add server so clean won't remove it
        server = Config.Server(name=backend_name, host='127.0.0.1', port=0)
        backend.add_server(server)

        # Render new cfg file
        if save:
            self.save_config()

    def disable_redirect(self, save=True):
        backend_name = 'redirect'

        # Remove the redirect backend
        for fe in self.proxy_config.frontends:
            fe.remove_usebackend(backend_name)

        # Clean the config
        self.clean_config(unit=backend_name, backend_name=backend_name, save=save)

    def get_frontend(self, port=None, create=True):
        port = str(port)
        frontend = None
        for fe in self.proxy_config.frontends:
            hookenv.log("Checking frontend for port {}".format(port), "DEBUG")
            hookenv.log("Port is: {}".format(fe.port), "DEBUG")
            if fe.port == port:
                hookenv.log("Using previous frontend", "DEBUG")
                frontend = fe
                break
        if frontend is None and create:
            hookenv.log("Creating frontend for port {}".format(port), "INFO")
            config_block = [Config.Bind('0.0.0.0', port, None)]
            frontend = Config.Frontend('relation-{}'.format(port), '0.0.0.0', port, config_block)
            self.proxy_config.frontends.append(frontend)
        return frontend

    def get_backend(self, name=None, create=True):
        backend = None
        for be in self.proxy_config.backends:
            if be.name == name:
                backend = be
        if not backend and create:
            hookenv.log("Creating backend {}".format(name))
            backend = Config.Backend(name=name, config_block=[])
            self.proxy_config.backends.append(backend)
        return backend

    def clean_config(self, unit, backend_name, save=True):
        # HAProxy units can't have / character, replace it so it doesn't fail on a common error of passing in the juju unit
        unit = unit.replace('/', '-')
        backend_name = backend_name.replace('/', '-')
        hookenv.log("Cleaning unit,backend: {},{}".format(unit, backend_name), 'DEBUG')

        # Remove acls and use_backend statements from frontends
        for fe in self.proxy_config.frontends:
            for ub in fe.usebackends():
                if ub.backend_condition == unit:
                    # Direct removal from config_block b/c the name will match
                    # others in a group since it isn't unique
                    fe.config_block.remove(ub)
            for acl in fe.acls():
                if acl.name == unit:
                    fe.remove_acl(acl.name)

        # Remove server statements from backends
        for be in self.proxy_config.backends:
            for server in be.servers():
                if server.name == unit:
                    be.remove_server(server.name)
                    # be.config_block.remove(server)

        # Remove any relation frontend if it doesn't have use_backend
        self.proxy_config.frontends[:] = [fe for fe in self.proxy_config.frontends if len(fe.usebackends()) > 0 or
                                          not fe.name.startswith('relation')]

        # Remove any backend with no server
        self.proxy_config.backends[:] = [be for be in self.proxy_config.backends if len(be.servers()) > 0]

        if save:
            self.save_config()

    def save_config(self):
        # Render new cfg file
        Render(self.proxy_config).dumps_to(self.proxy_config_file)
        host.service_reload('haproxy.service')

        # Check the juju ports match the config
        self.update_ports()

    def update_ports(self):
        opened_ports = str(subprocess.check_output(["opened-ports"]), 'utf-8').split('/tcp\n')
        hookenv.log("Opened ports {}".format(opened_ports), "DEBUG")
        for frontend in self.proxy_config.frontends:
            if frontend.port in opened_ports:
                if self.charm_config['enable-stats'] and self.charm_config['stats-local'] and\
                   self.charm_config['stats-port'] == int(frontend.port):
                    hookenv.log("Stats port set to be closed {}".format(frontend.port), "DEBUG")
                else:
                    hookenv.log("Port already open {}".format(frontend.port), "DEBUG")
                    opened_ports.remove(frontend.port)
            else:
                if self.charm_config['enable-stats'] and self.charm_config['stats-local'] and\
                   self.charm_config['stats-port'] == int(frontend.port):
                    hookenv.log("Not opening stats port {}".format(frontend.port), "DEBUG")
                else:
                    hookenv.log("Opening {}".format(frontend.port), "DEBUG")
                    hookenv.open_port(frontend.port)
        for port in opened_ports:
            if port:
                hookenv.log("Closing port {}".format(port), "DEBUG")
                hookenv.close_port(port)

    def enable_letsencrypt(self):
        hookenv.log("Enabling letsencrypt", "DEBUG")
        unit_name = 'letsencrypt'
        backend_name = 'letsencrypt-backend'

        frontend = self.get_frontend(80)
        if not self.available_for_http(frontend):
            hookenv.log("Port 80 not available for http use by letsencrypt", "ERROR")
            return  # TODO: Should I error here or is just returning with a log ok?

        # Only configure the rest if we haven't already done so to avoid checking every change for already existing
        first_run = True
        for acl in frontend.acls():
            if acl.name == unit_name:
                first_run = False
        if first_run:
            # Add ACL to the frontend
            acl = Config.Acl(name=unit_name, value='path_beg -i /.well-known/acme-challenge/')
            frontend.add_acl(acl)
            # Add usebackend
            use_backend = Config.UseBackend(backend_name=backend_name,
                                            operator='if',
                                            backend_condition=unit_name,
                                            is_default=False)
            frontend.add_usebackend(use_backend)

            # Get the backend, create if not present
            backend = self.get_backend(backend_name)

            # Add server to the backend
            attributes = ['']
            server = Config.Server(name=unit_name, host='127.0.0.1', port=self.letsencrypt_config['port'], attributes=attributes)
            backend.add_server(server)

            # Render new cfg file
            self.save_config()

        # Call the register function from the letsencrypt layer
        hookenv.log("Letsencrypt port: {}".format(self.letsencrypt_config['port']), 'DEBUG')
        hookenv.log("Letsencrypt domains: {}".format(self.charm_config['letsencrypt-domains']), 'DEBUG')
        if letsencrypt.register_domains() > 0:
            hookenv.log("Failed letsencrypt registration see /var/log/letsencrypt/letsencrypt.log", "ERROR")
            return  # TODO: Should I error here or is just returning with a log ok?

        # create the merged .pem for HAProxy
        self.merge_letsencrypt_cert()

        # Configure the frontend 443
        frontend = self.get_frontend(443)
        if not len(frontend.binds()[0].attributes):
            frontend.binds()[0].attributes.append('ssl crt {}'.format(self.cert_file))
        if first_run:
            frontend.add_acl(acl)
            frontend.add_usebackend(use_backend)
            if self.charm_config['destination-https-rewrite']:
                frontend.add_config(Config.Config('reqirep', 'Destination:\\ https(.*) Destination:\\ http\\\\1 '))
            self.save_config()

        # Add cron for renew
        self.add_cert_cron()

    def disable_letsencrypt(self, save=True):
        # Remove non-standard frontend configs
        frontend = self.get_frontend(443)
        frontend.binds()[0].attributes[:] = []  # Remove ssl cert attribute
        frontend.remove_config('reqirep', 'Destination:\\ https(.*) Destination:\\ http\\\\1 ')

        # Remove any standard config
        self.clean_config(unit='letsencrypt', backend_name='letsencrypt-backend', save=save)
        self.remove_cert_cron()

    def merge_letsencrypt_cert(self):
        letsencrypt_live_folder = '/etc/letsencrypt/live/{}/'.format(self.domain_name)
        with open(self.cert_file, 'wb') as outFile:
            with open(letsencrypt_live_folder + 'fullchain.pem', 'rb') as chainFile:
                outFile.write(chainFile.read())
            with open(letsencrypt_live_folder + 'privkey.pem', 'rb') as privFile:
                outFile.write(privFile.read())

    def renew_cert(self, full=True):
        hookenv.log("Renewing cert", "INFO")
        if full:
            # Calling a full disable/enable to clean and re-write the config to catch domain changes in the charm config
            hookenv.log("Performing full domain register", "INFO")
            self.disable_letsencrypt()
            self.enable_letsencrypt()
        else:
            hookenv.log("Performing renew only", "INFO")
            letsencrypt.renew()
            # create the merged .pem for HAProxy
            self.merge_letsencrypt_cert()

    def renew_upnp(self):
        hookenv.log("Renewing upnp port requests", "INFO")
        # check that open ports is accurate
        self.update_ports()
        # send upnp for ports even if they were already open
        opened_ports = str(subprocess.check_output(["opened-ports"]), 'utf-8').split('/tcp\n')
        opened_ports.remove('')
        for port in opened_ports:
            hookenv.log("Opening port {}".format(port), "INFO")
            hookenv.open_port(port)

    def release_upnp(self):
        hookenv.log("Releasing all upnp port requests", "INFO")
        # check that open ports is accurate
        self.update_ports()
        # send upnp for ports even if they were already open
        opened_ports = str(subprocess.check_output(["opened-ports"]), 'utf-8').split('/tcp\n')
        opened_ports.remove('')
        for port in opened_ports:
            hookenv.log("Closing port {}".format(port), "INFO")
            hookenv.close_port(port)

    def add_cron(self, action, interval):
        ''' action: name of the action to run
            interval: cron interval to set '''
        root_cron = CronTab(user='root')
        unit = hookenv.local_unit()
        directory = hookenv.charm_dir()
        action_path = directory + '/actions/{}'.format(action)
        command = "juju-run {unit} {action}".format(unit=unit, action=action_path)
        job = root_cron.new(command=command, comment="Charm cron for {}".format(action))
        job.setall(interval)
        root_cron.write()
        hookenv.log("Cron added: {}".format(action), "INFO")

    def remove_cron(self, action):
        root_cron = CronTab(user='root')
        try:
            job = next(root_cron.find_comment("Charm cron for {}".format(action)))
            root_cron.remove(job)
            root_cron.write()
        except StopIteration:
            hookenv.log("Cron was not present to remove", "WARN")
            pass
        hookenv.log("Cron removed: {}".format(action), "INFO")

    def add_cert_cron(self):
        self.add_cron('renew-cert', self.charm_config['cert-renew-interval'])

    def remove_cert_cron(self):
        self.remove_cron('renew-cert')

    def add_upnp_cron(self):
        self.add_cron('renew-upnp', self.charm_config['upnp-renew-interval'])

    def remove_upnp_cron(self):
        self.remove_cron('renew-upnp')
