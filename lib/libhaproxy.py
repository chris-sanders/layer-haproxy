"""Helper module for haproxy."""
import re
import subprocess
from distutils.version import StrictVersion

import pyhaproxy.config as haproxy_config
import reactive.letsencrypt as letsencrypt
from charmhelpers.core import hookenv, host
from charms import layer
from crontab import CronTab
from pyhaproxy.parse import Parser
from pyhaproxy.render import Render


class ProxyHelper:
    """Helper class for configuring haproxy."""

    def __init__(self):
        """Instantiate variables."""
        self.charm_config = hookenv.config()
        self.letsencrypt_config = layer.options("letsencrypt")
        # self.ppa = "ppa:vbernat/haproxy-{}".format(self.charm_config["version"])
        self.proxy_config_file = "/etc/haproxy/haproxy.cfg"
        self._proxy_config = None
        self.domain_name = self.charm_config["letsencrypt-domains"].split(",")[0]
        self.ssl_path = "/etc/haproxy/ssl/"
        self.cert_file = self.ssl_path + self.domain_name + ".pem"

    @property
    def ppa(self):
        """Return current PPA."""
        ppa = "ppa:vbernat/haproxy-{}".format(self.charm_config["version"])
        return ppa

    @property
    def proxy_config(self):
        """Parse and return proxy configuration."""
        if not self._proxy_config:
            self._proxy_config = Parser(self.proxy_config_file).build_configuration()

        return self._proxy_config

    def add_timeout_tunnel(self, timeout="1h", save=True):
        """Add tunnel_timeout setting to haproxy_config."""
        tunnel_config = haproxy_config.Config("timeout tunnel", "{}".format(timeout))
        defaults = self.proxy_config.defaults[0]

        for cfg in defaults.configs():
            if cfg.keyword == "timeout tunnel":
                defaults.remove_config(cfg)
        defaults.add_config(tunnel_config)

        if save:
            self.save_config()

    def get_config_names(self, configs):
        """Get configuration names from relation data."""
        names = []

        for index, config in enumerate(configs):
            remote_unit = hookenv.remote_unit().replace("/", "-") + "-{}".format(index)
            backend_name = config["group_id"] or remote_unit
            names.append((remote_unit, backend_name))

        return names

    def process_configs(self, configs):
        """Process related unit configuration."""
        for names, config in zip(self.get_config_names(configs), configs):
            remote_unit = names[0]
            backend_name = names[1]

            # For backwards compatibility and easy upgrades,
            # let's check, incase we've moved from the old <app>-<id>
            # style frontend names to the new multi-relation
            # <app>-<id>-<index> format - regex ^.*?(\d+)-(\d+)$
            legacy = self.legacy_name(backend_name)

            if legacy != backend_name:
                hookenv.log(
                    "Cleaning any legacy configs for {} ({})".format(
                        remote_unit, legacy
                    ),
                    "INFO",
                )
                self.clean_config(unit=legacy, backend_name=legacy, save=False)

            # Remove any prior configuration as it might have changed
            # do not write cfg file we still have edits to make
            hookenv.log(
                "Cleaning configs for remote {}, backend {}".format(
                    remote_unit, backend_name
                ),
                "DEBUG",
            )
            self.clean_config(unit=remote_unit, backend_name=backend_name, save=False)

            # Get the frontend, create if not present
            if config["mode"] == "tcp+tls":
                frontend = self.get_frontend(config["external_port"], tls=True)
            else:
                frontend = self.get_frontend(config["external_port"])

            # urlbase use to accept / now they are added automatically
            # to avoid errors strip it from old configs

            if config["urlbase"]:
                config["urlbase"] = config["urlbase"].rstrip("/")

            hookenv.log("Checking frontend {}".format(str(frontend)), "DEBUG")

            if config["mode"] == "http":
                if not self.available_for_http(frontend):
                    return {
                        "cfg_good": False,
                        "msg": "Port not available for http routing",
                    }

                # Add ACL's to the frontend

                if config["urlbase"]:
                    acl = haproxy_config.Acl(
                        name=remote_unit, value="path_beg {}/".format(config["urlbase"])
                    )
                    frontend.add_acl(acl)
                    acl = haproxy_config.Acl(
                        name=remote_unit, value="path {}".format(config["urlbase"])
                    )
                    frontend.add_acl(acl)

                if config["subdomain"]:
                    acl = haproxy_config.Acl(
                        name=remote_unit,
                        value="hdr_beg(host) -i {}".format(config["subdomain"]),
                    )
                    frontend.add_acl(acl)

                # Add use_backend section to the frontend
                use_backend = haproxy_config.UseBackend(
                    backend_name=backend_name,
                    operator="if",
                    backend_condition=remote_unit,
                    is_default=False,
                )
                frontend.add_usebackend(use_backend)

            if config["mode"] == "tcp" or config["mode"] == "tcp+tls":
                if not self.available_for_tcp(frontend, backend_name):
                    return {
                        "cfg_good": False,
                        "msg": ("Frontend already in use " "can not setup tcp mode"),
                    }

                mode_config = haproxy_config.Config("mode", "tcp")
                frontend.add_config(mode_config)

                # clean use backends for tcp backends, in case there is
                # any cruft left over from legacy configs

                for usebackend in frontend.usebackends():
                    frontend.remove_usebackend(usebackend.backend_name)

                use_backend = haproxy_config.UseBackend(
                    backend_name=backend_name,
                    operator="",
                    backend_condition="",
                    is_default=True,
                )
                frontend.add_usebackend(use_backend)

            # Get the backend, create if not present
            backend = self.get_backend(backend_name)

            # Set sensible connection checking parameter
            # by default. This will work for both TCP
            # and HTTP backends, if a group-id is specified,
            # nicer HTTP checks for HTTP backends will also
            # be enabled to perform HTTP requests as part of
            # checking backend health
            attributes = []

            if config["check"]:
                attributes = ["check fall 3 rise 2"]

            # Add server to the backend
            # Firstly, set the mode on the backedn to match
            # the frontend
            backend.add_config(haproxy_config.Config("mode", config["mode"]))

            # Now, for HTTP specific configuration

            if config["mode"] == "http":
                # Add cookie config if not already present
                cookie_found = False
                cookie = "cookie SERVERID insert indirect nocache"

                for test_config in backend.configs():
                    if cookie in test_config.keyword:
                        cookie_found = True

                if not cookie_found:
                    backend.add_config(haproxy_config.Config(cookie, ""))
                attributes.append("cookie {}".format(remote_unit))
                # Add httpchk option if not present

                if config["group_id"]:
                    httpchk_found = False
                    httpchk = "httpchk GET {} HTTP/1.0".format(config["urlbase"] or "/")

                    for test_option in backend.options():
                        if httpchk in test_option.keyword:
                            httpchk_found = True

                    if not httpchk_found:
                        backend.add_option(haproxy_config.Option(httpchk, ""))
                    attributes.append("check")
                # Add rewrite-path if requested and not present

                if config["rewrite-path"] and config["urlbase"]:
                    rewrite_found = False
                    rewrite = (
                        "http-request set-path " "%[path,regsub(^{}/?,/)]"
                    ).format(config["urlbase"])

                    for test_cfg in backend.configs():
                        if rewrite in test_cfg.keyword:
                            rewrite_found = True

                    if not rewrite_found:
                        backend.add_config(haproxy_config.Config(rewrite, ""))

                if config["acl-local"]:
                    if not backend.acl("local"):
                        backend.add_acl(
                            haproxy_config.Acl(
                                "local",
                                (
                                    "src 10.0.0.0/8 "
                                    "172.16.0.0/12 "
                                    "192.168.0.0/16 "
                                    "127.0.0.0/8 "
                                    "fd00::/8 "
                                    "fe80::/10 "
                                    "::1/128"
                                ),
                            )
                        )
                        backend.add_config(
                            haproxy_config.Config("http-request deny if !local", "")
                        )

                if config["proxypass"]:
                    proxy_found = False

                    for test_option in backend.options():
                        if "forwardfor" in test_cfg.keyword:
                            proxy_found = True

                    if not proxy_found:
                        backend.add_option(haproxy_config.Option("forwardfor", ""))

                    if config["external_port"] == 443:
                        forward_for = (
                            "http-request set-header " "X-Forwarded-Proto https"
                        )
                    else:
                        forward_for = (
                            "http-request set-header " "X-Forwarded-Proto http"
                        )
                    backend.add_config(haproxy_config.Config(forward_for, ""))

                if config["ssl"]:
                    if config["ssl-verify"]:
                        ssl_attrib = "ssl"
                    else:
                        ssl_attrib = "ssl verify none"
                    attributes.append(ssl_attrib)
            server = haproxy_config.Server(
                name=remote_unit,
                host=config["internal_host"],
                port=config["internal_port"],
                attributes=attributes,
            )
            backend.add_server(server)

        # Render new cfg file
        self.save_config()

        return {"cfg_good": True, "msg": "configuration applied"}

    def available_for_http(self, frontend):
        """Check if backend should be configured for HTTP."""
        if frontend.name == "stats":
            return False

        for config in frontend.configs():
            if "mode" in config.keyword and "tcp" in config.value:
                return False

        return True

    def legacy_name(self, name):
        """Translate between old and new naming on relation data."""
        regex = re.compile(r"^.*?(\d+)-(\d+)$")
        matches = regex.search(name)

        if matches:
            # we are dealing with a new-style indexed relation
            # we should remove any old-style config
            index_suffix = "-{}".format(matches.group(2))

            return name.rstrip(index_suffix)
        else:
            return name

    def available_for_tcp(self, frontend, backend_name):
        """Verify if related backend should be configured for TCP operation."""
        if len(frontend.acls()):
            return False

        if len(frontend.usebackends()):
            valid_backend = False

            for ub in frontend.usebackends():
                if ub.backend_name == backend_name:
                    valid_backend = True
                # also check for legacy backend name in
                # case we've upgrades

                if ub.backend_name == self.legacy_name(backend_name):
                    valid_backend = True

            if not valid_backend:
                return False

        return True

    def enable_stats(self, save=True):
        """Enable the stats enpoint."""
        # Remove any previous stats
        self.disable_stats(save=False)

        # Check that no frontend exists with conflicting port

        if (
            self.get_frontend(port=self.charm_config["stats-port"], create=False)
            is not None
        ):
            hookenv.log(
                "Stats port {} already in use".format(self.charm_config["stats-port"]),
                "ERROR",
            )

            if save:
                self.save_config()

            return False

        # Generate new front end for stats
        user_string = "{}:{}".format(
            self.charm_config["stats-user"], self.charm_config["stats-passwd"]
        )
        config_block = []
        config_block.append(
            haproxy_config.Bind("0.0.0.0", self.charm_config["stats-port"], None)
        )
        config_block.append(haproxy_config.Config("stats enable", ""))
        config_block.append(
            haproxy_config.Config("stats auth {}".format(user_string), "")
        )
        config_block.append(
            haproxy_config.Config(
                "stats uri {}".format(self.charm_config["stats-url"]), ""
            )
        )

        if self.charm_config["stats-local"]:
            config_block.append(
                haproxy_config.Acl(
                    "local",
                    (
                        "src 10.0.0.0/8 "
                        "172.16.0.0/12 "
                        "192.168.0.0/16 "
                        "127.0.0.0/8 "
                        "fd00::/8 "
                        "fe80::/10 "
                        "::1/128"
                    ),
                )
            )
            config_block.append(
                haproxy_config.Config("http-request deny if !local", "")
            )
        frontend = haproxy_config.Frontend(
            "stats", "0.0.0.0", str(self.charm_config["stats-port"]), config_block
        )
        self.proxy_config.frontends.append(frontend)

        if save:
            self.save_config()

        return True

    def disable_stats(self, save=True):
        """Disable the stats endpoint."""
        # Remove any previous stats frontend
        self.proxy_config.frontends[:] = [
            fe for fe in self.proxy_config.frontends if fe.name != "stats"
        ]

        if save:
            self.save_config()

    def enable_redirect(self, save=True):
        """Enable the generic redirect to HTTPS."""
        backend_name = "redirect"

        # remove any prevoius configureation
        self.disable_redirect(save=False)

        # Get or create frontend 80
        frontend = self.get_frontend(port=80)

        # Add use_backend section to the frontend
        use_backend = haproxy_config.UseBackend(
            backend_name=backend_name,
            operator="",
            backend_condition="",
            is_default=True,
        )
        frontend.add_usebackend(use_backend)

        # Get the backend, create if not present
        backend = self.get_backend(backend_name)

        # Add redirect option to the backend
        redirect_config = haproxy_config.Config("redirect scheme https", "")
        backend.add_config(redirect_config)

        # Add server so clean won't remove it
        server = haproxy_config.Server(name=backend_name, host="127.0.0.1", port=0)
        backend.add_server(server)

        # Render new cfg file

        if save:
            self.save_config()

    def disable_redirect(self, save=True):
        """Disable the generic redirect to HTTPS."""
        backend_name = "redirect"

        # Remove the redirect backend

        for fe in self.proxy_config.frontends:
            fe.remove_usebackend(backend_name)

        # Clean the config
        self.clean_config(unit=backend_name, backend_name=backend_name, save=save)

    def get_frontend(self, port=None, create=True, tls=False):
        """Find the frontend for the requested port."""
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
            print("TLS {} LE {} Port {}".format(tls, self.charm_config.get("enable-letsencrypt"), port))
            if tls and self.charm_config.get("enable-letsencrypt"):
                print("Found a TCP+TLS frontend")
                config_block = [haproxy_config.Bind("0.0.0.0", port, ["ssl crt {}".format(self.cert_file)])]
            else:
                config_block = [haproxy_config.Bind("0.0.0.0", port, None)]
            frontend = haproxy_config.Frontend(
                "relation-{}".format(port), "0.0.0.0", port, config_block
            )
            self.proxy_config.frontends.append(frontend)

        return frontend

    def get_backend(self, name=None, create=True):
        """Find the confiured backend based on the provided name, creating as needed."""
        backend = None

        for be in self.proxy_config.backends:
            if be.name == name:
                backend = be

        if not backend and create:
            hookenv.log("Creating backend {}".format(name))
            backend = haproxy_config.Backend(name=name, config_block=[])
            self.proxy_config.backends.append(backend)

        return backend

    def clean_config(self, unit, backend_name, save=True):
        """Clean the configuration of uneeded sections."""
        # HAProxy units can't have / character
        # replace it so it doesn't fail on a common error
        # from passing in the juju unit
        unit = unit.replace("/", "-")
        backend_name = backend_name.replace("/", "-")
        hookenv.log("Cleaning unit,backend: {},{}".format(unit, backend_name), "DEBUG")

        # Remove acls and use_backend statements from frontends

        for fe in self.proxy_config.frontends:
            for ub in fe.usebackends():
                # Match on name or condition, name is needed for TCP
                # frontends which use 'default_backend'

                if ub.backend_condition == unit or ub.backend_name == unit:
                    # Direct removal from config_block b/c the name will
                    # match others in a group since it isn't unique
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
        self.proxy_config.frontends[:] = [
            fe

            for fe in self.proxy_config.frontends

            if len(fe.usebackends()) > 0 or not fe.name.startswith("relation")
        ]

        # Remove any backend with no server
        self.proxy_config.backends[:] = [
            be for be in self.proxy_config.backends if len(be.servers()) > 0
        ]

        if save:
            self.save_config()

    def save_config(self):
        """Save the updated configuration."""
        # Render new cfg file
        Render(self.proxy_config).dumps_to(self.proxy_config_file)
        host.service_reload("haproxy.service")

        # Check the juju ports match the config
        self.update_ports()

    def update_ports(self):
        """Update open ports based on configuration so that Juju can expose them."""
        opened_ports = str(subprocess.check_output(["opened-ports"]), "utf-8").split(
            "/tcp\n"
        )
        hookenv.log("Opened ports {}".format(opened_ports), "DEBUG")

        for frontend in self.proxy_config.frontends:
            if frontend.port in opened_ports:
                if (
                    self.charm_config["enable-stats"]
                    and self.charm_config["stats-local"]
                    and self.charm_config["stats-port"] == int(frontend.port)
                ):
                    hookenv.log(
                        "Stats port set to be closed {}".format(frontend.port), "DEBUG"
                    )
                else:
                    hookenv.log("Port already open {}".format(frontend.port), "DEBUG")
                    opened_ports.remove(frontend.port)
            else:
                if (
                    self.charm_config["enable-stats"]
                    and self.charm_config["stats-local"]
                    and self.charm_config["stats-port"] == int(frontend.port)
                ):
                    hookenv.log(
                        "Not opening stats port {}".format(frontend.port), "DEBUG"
                    )
                else:
                    hookenv.log("Opening {}".format(frontend.port), "DEBUG")
                    hookenv.open_port(frontend.port)

        for port in opened_ports:
            if port:
                hookenv.log("Closing port {}".format(port), "DEBUG")
                hookenv.close_port(port)

    def supports_http2(self):
        """Check if HTTP/2 is enabled and supported."""
        if StrictVersion(self.charm_config.get("version")) >= StrictVersion("1.9"):
            return True

        return False

    def enable_letsencrypt(self):
        """Enable certbot for TLS certificate generation."""
        hookenv.log("Enabling letsencrypt", "DEBUG")
        unit_name = "letsencrypt"
        backend_name = "letsencrypt-backend"

        frontend = self.get_frontend(80)

        if not self.available_for_http(frontend):
            hookenv.log("Port 80 not available for http use by letsencrypt", "ERROR")

            return  # TODO: Should I error here, or is returning a log ok?

        # Only configure the rest if we haven't already done so to avoid
        # checking every change for already existing
        first_run = True

        for acl in frontend.acls():
            if acl.name == unit_name:
                first_run = False

        if first_run:
            # Add ACL to the frontend
            acl = haproxy_config.Acl(
                name=unit_name, value="path_beg -i /.well-known/acme-challenge/"
            )
            frontend.add_acl(acl)
            # Add usebackend
            use_backend = haproxy_config.UseBackend(
                backend_name=backend_name,
                operator="if",
                backend_condition=unit_name,
                is_default=False,
            )
            frontend.add_usebackend(use_backend)

            # Get the backend, create if not present
            backend = self.get_backend(backend_name)

            # Add server to the backend
            attributes = [""]
            server = haproxy_config.Server(
                name=unit_name,
                host="127.0.0.1",
                port=self.letsencrypt_config["port"],
                attributes=attributes,
            )
            backend.add_server(server)

            # Render new cfg file
            self.save_config()

        # Call the register function from the letsencrypt layer
        hookenv.log(
            "Letsencrypt port: {}".format(self.letsencrypt_config["port"]), "DEBUG"
        )
        hookenv.log(
            "Letsencrypt domains: {}".format(self.charm_config["letsencrypt-domains"]),
            "DEBUG",
        )

        if letsencrypt.register_domains() > 0:
            hookenv.log(
                (
                    "Failed letsencrypt registration see "
                    "/var/log/letsencrypt/letsencrypt.log"
                ),
                "ERROR",
            )

            return  # TODO: Should I error here or is just returning a log ok?

        # create the merged .pem for HAProxy
        self.merge_letsencrypt_cert()

        # Configure the frontend 443
        frontend = self.get_frontend(443)

        if not len(frontend.binds()[0].attributes):
            frontend.binds()[0].attributes.append("ssl crt {}".format(self.cert_file))

        if self.supports_http2():
            frontend.binds()[0].attributes.append("alpn h2,http/1.1")

        if first_run:
            frontend.add_acl(acl)
            frontend.add_usebackend(use_backend)

            if self.charm_config["destination-https-rewrite"]:
                frontend.add_config(
                    haproxy_config.Config(
                        "reqirep", "Destination:\\ https(.*) Destination:\\ http\\\\1 "
                    )
                )
            self.save_config()

        # Add cron for renew
        self.add_cert_cron()

    def disable_letsencrypt(self, save=True):
        """Disable certbot usage."""
        # Remove non-standard frontend configs
        frontend = self.get_frontend(443)
        frontend.binds()[0].attributes[:] = []  # Remove ssl cert attribute
        frontend.remove_config(
            "reqirep", "Destination:\\ https(.*) Destination:\\ http\\\\1 "
        )

        # Remove any standard config
        self.clean_config(
            unit="letsencrypt", backend_name="letsencrypt-backend", save=save
        )

        # Remove ssl crt binds
        for fe in self.proxy_config.frontends:
            fe.binds()[0].attributes[:] = []  # Remove ssl cert attribute

        self.remove_cert_cron()

    def merge_letsencrypt_cert(self):
        """Convert certbot certificate into the format needed for haproxy."""
        letsencrypt_live_folder = "/etc/letsencrypt/live/{}/".format(self.domain_name)
        with open(self.cert_file, "wb") as out_file:
            with open(letsencrypt_live_folder + "fullchain.pem", "rb") as chain_file:
                out_file.write(chain_file.read())
            with open(letsencrypt_live_folder + "privkey.pem", "rb") as priv_file:
                out_file.write(priv_file.read())

    def renew_cert(self, full=True):
        """Renew certificates."""
        hookenv.log("Renewing cert", "INFO")

        if full:
            # Calling a full disable/enable to clean and re-write the config
            # to catch domain changes in the charm config
            hookenv.log("Performing full domain register", "INFO")
            self.disable_letsencrypt()
            self.enable_letsencrypt()
        else:
            hookenv.log("Performing renew only", "INFO")
            letsencrypt.renew()
            # create the merged .pem for HAProxy
            self.merge_letsencrypt_cert()
            host.service_reload("haproxy.service")

    def renew_upnp(self):
        """Renew upnp port forward."""
        hookenv.log("Renewing upnp port requests", "INFO")
        # check that open ports is accurate
        self.update_ports()
        # send upnp for ports even if they were already open
        opened_ports = str(subprocess.check_output(["opened-ports"]), "utf-8").split(
            "/tcp\n"
        )
        opened_ports.remove("")

        for port in opened_ports:
            hookenv.log("Opening port {}".format(port), "INFO")
            hookenv.open_port(port)

    def release_upnp(self):
        """Release upnp port forward."""
        hookenv.log("Releaseing all upnp port requests", "INFO")
        # check that open ports is accurate
        self.update_ports()
        # send upnp for ports even if they were already open
        opened_ports = str(subprocess.check_output(["opened-ports"]), "utf-8").split(
            "/tcp\n"
        )
        opened_ports.remove("")

        for port in opened_ports:
            hookenv.log("Closing port {}".format(port), "INFO")
            hookenv.close_port(port)

    def add_cron(self, action, interval):
        """Add a cron job for the provided action to run at the provided interval."""
        root_cron = CronTab(user="root")
        unit = hookenv.local_unit()
        directory = hookenv.charm_dir()
        action_path = directory + "/actions/{}".format(action)
        command = "juju-run {unit} {action}".format(unit=unit, action=action_path)
        job = root_cron.new(command=command, comment="Charm cron for {}".format(action))
        job.setall(interval)
        root_cron.write()
        hookenv.log("Cron added: {}".format(action), "INFO")

    def remove_cron(self, action):
        """Remove cron job for provided action."""
        root_cron = CronTab(user="root")
        try:
            job = next(root_cron.find_comment("Charm cron for {}".format(action)))
            root_cron.remove(job)
            root_cron.write()
        except StopIteration:
            hookenv.log("Cron was not present to remove", "WARN")
            pass
        hookenv.log("Cron removed: {}".format(action), "INFO")

    def add_cert_cron(self):
        """Add cron job for renewing certificates."""
        self.add_cron("renew-cert", self.charm_config["cert-renew-interval"])

    def remove_cert_cron(self):
        """Remove cron job for renewing certificates."""
        self.remove_cron("renew-cert")

    def add_upnp_cron(self):
        """Add a cron job for refreshing upnp port forwards."""
        self.add_cron("renew-upnp", self.charm_config["upnp-renew-interval"])

    def remove_upnp_cron(self):
        """Remove the cron job for refreshing upnp port forwards."""
        self.remove_cron("renew-upnp")

    def check_version(self):
        """Chcek version for upgrade support."""
        if host.get_distrib_codename() == "xenial":
            supported_versions = ("1.7",)

            if self.charm_config["version"] not in supported_versions:
                msg = "Version {} must be in {} for xenial".format(
                    self.charm_config["version"], supported_versions
                )

                return (False, msg, supported_versions[0])
            else:
                return (True, "Version supported", None)
        elif host.get_distrib_codename() == "bionic":
            supported_versions = ("1.8", "1.9")

            if self.charm_config["version"] not in supported_versions:
                msg = "Version {} must be in {} for bionic".format(
                    self.charm_config["version"], supported_versions
                )

                return (False, msg, supported_versions[0])
            else:
                return (True, "Version supported", None)

        return (False, "Version check failed")
