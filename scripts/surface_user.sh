source /usr/local/bin/virtualenvwrapper.sh
workon pckr
export PCKR_USERNAME=$1
pckr init_user
pckr surface_user