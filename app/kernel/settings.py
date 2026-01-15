from pathlib import Path
from datetime import timedelta
from kernel.config import Config


BASE_DIR = Path(__file__).resolve().parent.parent

USE_TZ = True

USE_I18N = True

TIME_ZONE = "UTC"

DEBUG = Config.debug

LANGUAGE_CODE = "en-us"

ROOT_URLCONF = "kernel.urls"

AUTH_USER_MODEL = "core.User"

STATIC_URL = Config.static_url

SECRET_KEY = Config.secret_key

STATIC_ROOT = BASE_DIR / "static"

ALLOWED_HOSTS = Config.allowed_hosts

ASGI_APPLICATION = "kernel.asgi.application"

DATABASES = dict(default=Config.database_options)

CSRF_TRUSTED_ORIGINS = Config.csrf_trusted_origins

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "daphne",
    "channels",
    "django.contrib.staticfiles",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.admin",
    "django.contrib.auth",
    "kernel",
    "core",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "core.security.middleware.SecurityMiddleware",
    "core.security.middleware.ReplayProtectionMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

SIMPLE_JWT = {
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': True,
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=8),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "core.auth.handlers.JwtAuthentication",
        "core.auth.handlers.HmacAuthentication",
    ],
    'EXCEPTION_HANDLER': 'api.exceptions.handle_exception',
}

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

if DEBUG:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels.layers.InMemoryChannelLayer",
        },
    }
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "unique-snowflake",
        }
    }
else:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [Config.redis_url],
            },
        },
    }
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": Config.cache_url,
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]
