# Overview

pckr (picker) is

- a P2P network discovery framework
- a `public_key` infrastructure
- a messaging service
- an end-to-end encrypted file transfer service
- a possible security hazard

## Mechanism By Which The Above is Accomplished

This is a high-level view of how the network is created and how users are bootstrapped into it.

Instructions are provided elsewhere.

- `u1` is created with a public/private key pair
- `u1` can then expose an interface to the world (we which we call their `surface`) at an `ip:port` combination
    - the `surface` will listen for incoming `frame`s and react to them
- `u1` will be very lonely indeed until bootstrapped into a network
- `u1` is encouraged to contact a friend (`u2`) out-of-band to exchange `ip:port` info
- `u1` can then stitch `u2` into their `ipcache`
- at this point either `u1` or `u2` can request the other's `public_key`
- if `u1` initiates the `public_key` exchange, `u1` volunteers their `public_key` freely
    - no cryptographic protocol is established beween the users at this point, so `u1`'s `public_key` is transmitted in the clear
- `u2` can accept this request for their `public_key`
- `u2` can also store `u1`'s `public_key` which was just transmitted
- `u2` will encrypt their `public_key` with a password, and encrypt that password with `u1`'s `public_key`, and send it back
- `u1` can decrypt the password using their private key, and then decrypt `u2`'s `public_key` using the password
- at this point `u1` and `u2` are sharing `public_key`s, and are aware of each other's `ip:port`s
- both `u1` and `u2` will periodically seek each other out, to ping the other and challenge their stored `public_key`s
- `u1` and `u2` are also expected to transmit `frame`s from users that are surfacing into the network, and users that are seeking other users
    - more details on both follow
- `u1` and `u2` are also expected to transmit `frame`s pertaining to the health of the network
    - specifically, `frame`s are sent out to gather information about the health of the network topology
    - `u1` and `u2` would do well to heed the advice of these `frame`s, and challenge or expel inconsistently recognized users in their reachable networks

## Philosophically Though

- my first drafts of the client include a server, which coördinated `ip:port` combinations for certain users. very early drafts also included the `public_key` of each user, in plain text, as a column, sitting on a Postgres database behind a REST API
- the challenge was to make it a true P2P network, with no coördinating server
- since no coördinating server was desirable, every client has to ensure that they remain a part of the network
- for this reason, the network is hereby referred to as a `murmuration`
- no such thing is true
- each client is responsible for tagging-along by informing the network of their whereabouts ("surfacing") or verifying the `ip:port` and cryptographical links of their contacts ("seeking")
- clients also have a role to play in ensuring the health of their network topology, by propagating `frames` which aim to collect information about the consistency of the network
    - such network topology checks might also then inform clients about inconsistently recognized users, which the client could then choose to expel from their `ipcache`, or challenge, as they wish
    - every client is also free to do nothing
- it might seem a pain to bootstrap over the phone or WhatsApp or Telegram or what have you but you can create small networks isolated from the outside world

## Users and Authentication

- user information is thrown into a directory tree
- the client was written to allow unfettered access to users on the same account or physical machine as you
- no passwords exist. anyone that has access to your computer has access to your pckr "account"
- users are not guaranteed unique across a network of any size greater than 1
    - `public_key` challenges are used when needed to establish the identity of your contacts
    - it's entirely possible that your `ipcache` will become overrun with duplicate usernames of people purporting to be who they say they are. woe to you and them! `public_key` challenges to the rescue.
    - seriously though this could be a problem
    - remember to contact your contacts out of band as appropriate to verify their identities

## Network Topology

- the health of the network is achieved by voluntary participation in two activities
    - seeking users
    - surfacing
- clients are encouraged to surface on startup
    - they need to tell all of the contacts they have in their `ipcache` that they are alive
    - they do this by encrypting their `ip:port` using their contacts' `public_key`s, and transmitting that information to each contact
- clients are also encouraged to `ping` and `challenge` all users they have knowledge of
    - clients can `ping` or `challenge` any conact in their `ipcache`
- they can also `seek` contacts that they have a `public_key` for

### Surfacing

### Seeking

- `u1` can seek out any user in their reachable network, if they know that user's `public_key`
- `u1` encrypts a password using `u2`'s public key
- they also encrypt their own `ip:port` combination, along with their `username`
- they also generate a random `seek_token`, which they encrypt using the password, and send that along as well
- the `seek_token` is stored locally
- they send the message out to every contact they have in their `ipcache`
- each contact can try to decrypt the password
- if they can decrypt it, they reply directly to `u1` using the `ip:port` combination they get by decrypting it from the `frame`'s `payload`
- `u1` can process the `seek_user_response` to store `u2`'s `ip:port` in their `ipcache`
- `u2` is free to store `u1`'s `ip:port` combination as well
    - `u2` is equally free to challenge `u1` before doing so
    
    
### Network Topology Checks

## Challenges

- `u1` can challenge `u2` in 2 ways:
    - does `u2` have the private key that matches the `public_key` that `u1` has stored for them
        - `u1` encrypts an arbitrary piece of data using `u1`'s `public_key` and sends it to `u2`
        - `u2` responds by using their `private_key` to decrypt the data and send it back
        - `u1` can verify the data
        - if it matches, the challenge has succeeded
    - does `u2` have `u1`'s `public_key`
        - `u1` sends a piece of data to `u2`
        - `u2` encrypts it using the `public_key` of `u1`
        - `u1` decrypts it using their `private_key`
- by using both methods, `u1` and `u2` can verify a solid cryptographical link
- either user can also ensure that the user presenting at a certain `ip:port` is who they claim to be
- this makes the exchange of `public_keys`s as early as possible quite important for the health of the network

## IPCache

## Security Concerns

[keep fighting](docs/security_concerns.md)

## File Transfer

- since everyone is so well connected and cryptographic protocols are established and verifiable between users, we might as well also send files to each other
