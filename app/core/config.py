import json
import dj_database_url
from bootkit import execute
from bootkit.casts import to_bool
from bootkit.mezages import mzg_hosts, mzg_to_bool
from bootkit.config_meta import ConfigMeta, variable, VariableError


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
        raise VariableError(mzg_to_bool.text)

    @variable
    def database_options(self, ctx):
        database_url = ctx.load.env("DATABASE_URL")
        return dj_database_url.parse(database_url)

    @variable
    def allowed_hosts(self, ctx):
        value = ctx.load.env("ALLOWED_HOSTS")

        if value is None:
            debug = ctx.load.var("debug")[0]
            value = '["*"]' if debug == True else "[]"

        value = execute(json.loads, value)[0]

        if isinstance(value, list):
            return value

        raise VariableError(mzg_hosts.text)

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
