# Here is how

- create an ipcache module to cache ip, ports for usernames

- contact your contact over messenger or phone
    - get their ip, port

- add them to your ipcache

- then request their public key
    - get their public key

- then in the future when you need to find someone, you can 
    - create a dict
        - your public key
        - your ip
        - your port
        - challenge text (you'll need to store this on the client side)
        - your username
    - then encrypt it with a password
    - encrypt the password with their public key
    - send a frame
        - "seek_user"
        - payload as described above
        - password encrypted with their public key
        - message_id

- other users will try to decrypt it
    - if they can, then they can respond to the asking user directly
        - encrypt the payload with a password
        - encrypt that password with their public key
        - respond with the challenge text
    - if they can't, they broadcast the message

- 