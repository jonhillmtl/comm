# Overview

pckr (picker) is

- a P2P network discovery framework
- a public key infrastructure
- a messaging service
- an end-to-end encrypted file transfer service
- a possible security hazard

## Mechanism By Which The Above is Accomplished

This is a high-level view of how the network is created and how users are bootstrapped into it.

Instructions are provided elsewhere.

- users are created with a public/private key pair
- they then expose an interface to the world (we which we call their surface) at an ip:port combo
    - this interface will listen for incoming frames and react to them
- the user will be very lonely indeed until bootstrapped into a network
- the user (u1) is encouraged to contact a friend (u2) out-of-band to exchange ip:port info
- u1 can then stitch u2 into their `ipcache`
- at this point either u1 or u2 can request the other's public key
- if u1 initiates the public key exchange, they volunteer their key freely
    - no cryptographic protocol is established beween the users at this point, so their public key is transmitted in the clear
- u2 can accept this request for their public key
- u2 can also store u1's public key which was just transmitted
- u2 will encrypt their public key with a password, and encrypt that password with u1's public key, and send it back
- u1 can decrypt the password using their private key, and then decrypt u2's public key using the password
- at this point u1 and u2 are sharing public keys, and are aware of each other's ip:ports
- both u1 and u2 will periodically seek each other out, to ping the other and challenge their stored public keys
- u1 and u2 are also expected to transmit frames from users that are surfacing into the network, and users that are seeking other users
    - more details on both follow
- u1 and u2 are also expected to transmit frames pertainging to the health of the network
    - specifically, frames are sent out to gather information about the health of the network topology
    - u1 and u2 would do well to heed the advice of these frames, and challenge or expel inconsistently recognized users in their reachable networks

## File Transfer

- since everyone is so well connected and cryptographic protocols are established and verifiable between users, we might as well also send files to each other

## Philosophically Though

- it might seem a pain to bootstrap over the phone or WhatsApp or Telegram or what have you but you can create small networks isolated from the outside world

## Users and Authentication

- user information is thrown into a directory tree
- the client was written to allow unfettered access to users on the same account or physical machine as you
- no passwords exist. anyone that has access to your computer has access to your pckr "account"
- users are not guaranteed unique across a network of any size greater than 1
    - public key challenges are used when needed to establish the identity of your contacts
    - it's entirely possible that your ipcache will become overrun with duplicate usernames of people purporting to be who they say they are. woe to you and them! public key challenges to the rescue.
    - seriously though this could be a problem
    - remember to contact your contacts out of band as appropriate to verify their identities
