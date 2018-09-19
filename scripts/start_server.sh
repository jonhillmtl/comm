source /usr/local/bin/virtualenvwrapper.sh
workon pckr_client
export FLASK_APP=__init__.py
cd pckr_server
flask run