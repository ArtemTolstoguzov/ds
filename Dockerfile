FROM python:3.10

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

RUN mkdir -p /src/

RUN apt-get update

COPY Pipfile* /src/
RUN cd src/ && \
    pip install pipenv && \
    pipenv install --system --deploy --ignore-pipfile


COPY * /src/
WORKDIR /src/
