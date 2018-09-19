source /usr/local/bin/virtualenvwrapper.sh
workon pckr_client
export PCKR_USERNAME=$1
pckr_client initiate_user
pckr_client broadcast_user