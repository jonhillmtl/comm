# move the files out of the way
rm -rf /Users/jon/pckr/
ttab ./scripts/surface_user.sh 123
ttab ./scripts/surface_user.sh 234
ttab ./scripts/surface_user.sh 345
ttab ./scripts/surface_user.sh 456
ttab ./scripts/surface_user.sh 567
ttab ./scripts/surface_user.sh 678
ttab ./scripts/surface_user.sh 789
ttab ./scripts/surface_user.sh 890

sleep 5;
python ./scripts/stitch_network.py