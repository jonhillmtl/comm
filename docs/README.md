# Overview

pckr (picker) is

- a P2P `network` discovery framework
- a `public_key` infrastructure
- a messaging service
- an end-to-end encrypted file transfer service
- a possible security hazard

## Mechanism By Which The Above is Accomplished

This is a high-level view of how the `network` is created and how users are bootstrapped into it.

Instructions are provided elsewhere.

- `user1` is created with a `public_key`/`private_key` pair
- `user1` can then expose an interface to the world (we which we call their `surface`) at an `ip:port` combination
    - the `surface` will listen for incoming `frame`s and react to them
- `user1` will be very lonely indeed until bootstrapped into a `network`
- `user1` is encouraged to contact a friend (`user2`) out-of-band to exchange `ip:port` info
- `user1` can then stitch `user2` into their `ipcache`
- at this point either `user1` or `user2` can request the other's `public_key`
- if `user1` initiates the `public_key` exchange, `user1` volunteers their `public_key` freely
    - no cryptographic protocol is established beween the users at this point, so `user1`'s `public_key` is transmitted in the clear
- `user2` can accept this request for their `public_key`
- `user2` can also store `user1`'s `public_key` which was just transmitted
- `user2` will encrypt their `public_key` with a `password`, and encrypt that `password` with `user1`'s `public_key`, and send it back
- `user1` can decrypt the `password` using their `private_key`, and then decrypt `user2`'s `public_key` using the `password`
- at this point `user1` and `user2` are sharing `public_key`s, and are aware of each other's `ip:port`s
- both `user1` and `user2` will periodically `seek_user` to seek each other out, to `ping` the other and `challenge` their stored `public_key`s
- `user1` and `user2` are also expected to transmit `frame`s from users that are surfacing into the `network`, and users that are `seek_user`ing other users
    - more details on both follow
- `user1` and `user2` are also expected to transmit `frame`s pertaining to the health of the `network`
    - specifically, `frame`s are sent out to gather information about the health of the `network` topology
    - `user1` and `user2` would do well to heed the advice of these `frame`s, and challenge or expel inconsistently recognized users in their reachable `network`

## Philosophically Though

- my first drafts of the client include a server, which coördinated `ip:port` combinations for certain users. very early drafts also included the `public_key` of each user, in plain text, as a column, sitting on a Postgres database behind a REST API
- the challenge was to make it a true P2P `network`, with no coördinating server
- since no coördinating server was desirable, every client has to ensure that they remain a part of the `network`
- for this reason, the `network` is hereby referred to as a `murmuration`
- no such thing is true
- each client is responsible for tagging-along by informing the `network` of their whereabouts ("surfacing") or verifying the `ip:port` and cryptographical links of their contacts ("seeking")
- clients also have a role to play in ensuring the health of their `network` topology, by propagating `frames` which aim to collect information about the consistency of the `network`
    - such `network` topology checks might also then inform clients about inconsistently recognized users, which the client could then choose to expel from their `ipcache`, or challenge, as they wish
    - every client is also free to do nothing
- it might seem a pain to bootstrap over the phone or WhatsApp or Telegram or what have you but you can create small `network`s isolated from the outside world

## Users and Authentication

- user information is thrown into a directory tree
- the client was written to allow unfettered access to users on the same account or physical machine as you
- no passwords exist. anyone that has access to your computer has access to your pckr "account"
- users are not guaranteed unique across a `network` of any size greater than 1
    - `public_key` challenges are used when needed to establish the identity of your contacts
    - it's entirely possible that your `ipcache` will become overrun with duplicate usernames of people purporting to be who they say they are. woe to you and them! `public_key` challenges to the rescue.
    - seriously though this could be a problem
    - remember to contact your contacts out of band as appropriate to verify their identities

## Network Topology

- the health of the `network` is achieved by voluntary participation in two activities
    - `seek_users`
    - `surface_user`
- clients are encouraged to `surface_user` on startup
    - they need to tell all of the contacts they have in their `ipcache` that they are alive
    - they do this by encrypting their `ip:port` using their contacts' `public_key`s, and transmitting that information to each contact
- clients are also encouraged to `ping` and `challenge` all users they have knowledge of
    - clients can `ping` or `challenge` any conact in their `ipcache`
- they can also `seek` contacts that they have a `public_key` for

### Surfacing

### Seeking

- `user1` can seek out any user in their reachable `network`, if they know that user's `public_key`
- `user1` prepares a `payload` for destined for `user2`
    - `user1` encrypts a `password` using `user2`'s `public_key`
    - they encrypt their own `ip:port` combination as `json`, along with their `username`, using the `password`
    - they also generate a random `seek_token`, which they encrypt using the `password`
- the `seek_token` is stored locally
- they send the `frame` out to every contact they have in their `ipcache`
- each contact can try to decrypt the `password`
- if they can decrypt it, they reply directly to `user1` using the `ip:port` combination they get by decrypting it from the `frame`'s `payload`
- `user1` can process the `seek_user_response` to store `user2`'s `ip:port` in their `ipcache`
    - `user1` can ensure that `user2` send back the correct `seek_token`
- `user2` is free to store `user1`'s `ip:port` combination as well
    - `user2` is equally free to challenge `user1` before doing so
    
    
### Network Topology Checks

## Challenges

- `user1` can challenge `user2` in 2 ways:
    - does `user2` have the `private_key` that matches the `public_key` that `user1` has stored for them
        - `user1` encrypts an arbitrary piece of data using `user1`'s `public_key` and sends it to `user2`
        - `user2` responds by using their `private_key` to decrypt the data and send it back
        - `user1` can verify the data
        - if it matches, the challenge has succeeded
    - does `user2` have `user1`'s `public_key`
        - `user1` sends a piece of data to `user2`
        - `user2` encrypts it using the `public_key` of `user1`
        - `user1` decrypts it using their `private_key`
- by using both methods, `user1` and `user2` can verify a solid cryptographical link
- either user can also ensure that the user presenting at a certain `ip:port` is who they claim to be
- this makes the exchange of `public_keys`s as early as possible quite important for the health of the `network`

## IPCache

- users can (and even must) store the `ip:port` of their contacts in their `ipcache`
- the contents of the `ipcache` are updated or adjusted in response to particular `frames`
    - `user2` can store the `ip:port` of `user1` that is included in a `seek_user` `frame`
    - `user1` can store the `ip:port` of `user2` that they might receive in a `seek_user_response` `frame`
- users can also stich a contact into their `network` manually
    - in fact, this is how they are bootstrapped into the `network`

## Security Concerns

[keep fighting](docs/security_concerns.md)

## File Transfer

- since everyone is so well connected and cryptographic protocols are established and verifiable between users, we might as well also send files to each other
