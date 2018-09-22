# move the files out of the way
rm -rf /Users/jon/pckr/

ttab ./scripts/surface_user.sh trapst
ttab ./scripts/surface_user.sh brenda
ttab ./scripts/surface_user.sh jasmin
ttab ./scripts/surface_user.sh dolory
ttab ./scripts/surface_user.sh murbid


sleep 5;
python ./scripts/stitch_network.py