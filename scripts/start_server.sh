source /usr/local/bin/virtualenvwrapper.sh
workon pckr
export PCKR_DEBUG=1
export FLASK_APP=__init__.py
cd pckr_server
flask run