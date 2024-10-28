#------------------------------------------
# Base
#------------------------------------------

FROM python:3.12-alpine3.20 as base

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN pip install --no-cache-dir --upgrade pip 2>/dev/null
RUN pip install --no-cache-dir --root-user-action=ignore pipenv
RUN apk update && apk add gcc bash wait4x musl-dev python3-dev postgresql-dev

WORKDIR /app

COPY ./app/Pipfile ./app/Pipfile.lock ./
RUN pipenv install --system --deploy

COPY ./app/ ./

#------------------------------------------
# Local
#------------------------------------------

FROM base as local

#------------------------------------------
# Remote
#------------------------------------------

FROM base as remote

CMD daphne -b 0.0.0.0 -p $PORT kernel.asgi:application
