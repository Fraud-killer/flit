from pathlib import Path
from datetime import timedelta
from kernel.config import Config


BASE_DIR = Path(__file__).resolve().parent.parent

USE_TZ = True

USE_I18N = True

TIME_ZONE = "UTC"

DEBUG = Config.debug

LANGUAGE_CODE = "en-us"

CSRF_TRUSTED_ORIGINS = ["https://flit-production-41839371145.us-central1.run.app"]

ROOT_URLCONF = "kernel.urls"

AUTH_USER_MODEL = "core.User"

STATIC_URL = Config.static_url

SECRET_KEY = Config.secret_key

STATIC_ROOT = BASE_DIR / "static"

ALLOWED_HOSTS = Config.allowed_hosts

WSGI_APPLICATION = "kernel.wsgi.application"

DATABASES = dict(default=Config.database_options)

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


INSTALLED_APPS = [
    "django.contrib.contenttypes",
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
        "authentication.handlers.JwtAuthentication",
        "authentication.handlers.HmacAuthentication",
    ],
    'EXCEPTION_HANDLER': 'api.exceptions.handle_any_exception',
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
