# move the files out of the way
rm -rf /Users/jon/pckr/

ttab ./scripts/surface_user.sh trapst
ttab ./scripts/surface_user.sh brenda
ttab ./scripts/surface_user.sh jasmin
# ttab ./scripts/surface_user.sh rescha
# ttab ./scripts/surface_user.sh gyrilh

ttab tail -f logs/assert.log
ttab tail -f logs/surface.log
ttab tail -f logs/debug.log

sleep 10;
python ./scripts/stitch_network.py

