source /usr/local/bin/virtualenvwrapper.sh
workon pckr_client
export PCKR_USERNAME=$1
pckr init_user
pckr surface_user