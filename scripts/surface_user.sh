source /usr/local/bin/virtualenvwrapper.sh
workon pckr_client
export PCKR_USERNAME=$1
pckr_client init_user
pckr_client surface_user