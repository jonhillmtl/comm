# move the files out of the way
mv ~/pckr/ ~/pckr_bk/

ttab ./scripts/start_server.sh
sleep 2
curl -X POST http://127.0.0.1:5000/db/clear/
sleep 2
ttab ./scripts/broadcast_user.sh 123
ttab ./scripts/broadcast_user.sh 234
ttab ./scripts/command.sh 123
ttab ./scripts/command.sh 234