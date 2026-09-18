import json
import dj_database_url
from devkit import execute
from devkit.casts import to_bool
from devkit.messages import msg_to_bool
from devkit.config_meta import variable, ConfigMeta, VariableError


class Config(metaclass=ConfigMeta):
    @variable
    def mcrypt_key(self, ctx):
        return ctx.load.env("MCRYPT_KEY")

    @variable
    def secret_key(self, ctx):
        return ctx.load.env("SECRET_KEY")

    @variable
    def debug(self, ctx):
        value = ctx.load.env("DEBUG", False)
        value, error = execute(to_bool, value)
        if not error: return value
        raise VariableError(msg_to_bool.text)

    @variable
    def database_options(self, ctx):
        database_url = ctx.load.env("DATABASE_URL")
        return dj_database_url.parse(database_url)

    @variable
    def csrf_trusted_origins(self, ctx):
        value = ctx.load.env("CSRF_TRUSTED_ORIGINS")
        value = "[]" if value is None else value
        return json.loads(value)

    @variable
    def allowed_hosts(self, ctx):
        value = ctx.load.env("ALLOWED_HOSTS")

        if value is None:
            debug = ctx.load.var("debug")[0]
            value = '["localhost", "127.0.0.1"]' if debug == True else "[]"

        return json.loads(value)

    @variable
    def secure_ssl_redirect(self, ctx):
        value = ctx.load.env("SECURE_SSL_REDIRECT", True)
        value, error = execute(to_bool, value)
        if not error: return value
        raise VariableError(msg_to_bool.text)

    @variable
    def geoip_db_path(self, ctx):
        return ctx.load.env("GEOIP_DB_PATH")

    @variable
    def threat_list_url(self, ctx):
        return ctx.load.env(
            "THREAT_LIST_URL",
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        )

    @variable
    def static_url(self, ctx):
        value = ctx.load.env("STATIC_URL", "/static")
        return value.strip("/") + "/"

    @variable
    def fingerprint_server_api_key(self, ctx):
        return ctx.load.env("FINGERPRINT_SERVER_API_KEY")

    @variable
    def fingerprint_management_api_key(self, ctx):
        return ctx.load.env("FINGERPRINT_MANAGEMENT_API_KEY")

    @variable
    def redis_url(self, ctx):
        return ctx.load.env("REDIS_URL", "redis://localhost:6379/0")

    @variable
    def cache_url(self, ctx):
        return ctx.load.env("CACHE_URL", "redis://localhost:6379/1")
