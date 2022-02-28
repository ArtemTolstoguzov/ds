## RUN
* _SERVER_: docker-compose up -d
* _CLIENT_:
  * pip install pipenv
  * pipenv install --ignore-pipfile
  * pipenv shell
  * python cli_client.py localhost:5002 PORT