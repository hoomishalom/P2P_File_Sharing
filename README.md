# README

## Requirements

- libssl

you can download all requirements using this command in the terminal

```shell
sudo apt-get install libssl-dev
```

## Explanation About The Project

In short it's a simple decentralized encrypted file sharing program.

In more detail, firstly for a node to connect to the network it will need to scan the network, get the names of all the currently connected nodes and then prompt the user to enter a unique name, if it will pick a name which has already been used other nodes won't accept its connection and thus won't work.

After the node talked to all other nodes on the network and saving all their (name, address) pairs it will give the user a TUI with the options to:

- list all connected nodes
- view incoming requests
- request to send a file
- **[MIGHT ADD MORE]**

When a node wants to send a file it will send a request to the receiving node, if the receiving node agrees the receiver node will send its RSA **public** key, then the sender node will encrypt its AES key using the **public** RSA key it received (the AES key is unique to each transfer) it will send it back to the receiver node, the receiver node will decrypt the message using its RSA **private** key, save the output which is the AES key (which is unique for each transfer) and send a confermation packet back to the sender node.
Both nodes now have the AES key, so the sender node will encrypt the file using AES in GCM mode using the key and a random generated IV, it will save the encrypted file in a temporary file and the IV will be saved in a variable, then the sender node will send the encrypted file and the IV (which will be sent in plaintext, this doesn't cause any security concerns), all thats left is for the receiver node to save the encrypted file in a temporary file, decrypt it and save the result in the desired location.
