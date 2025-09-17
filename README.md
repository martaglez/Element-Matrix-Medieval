# Element-Matrix-Implementation
In this repository is included a python implementation over criptography of a medieval cipher implementation (Atbash + Vigenère) to communicate betweeen users via matrix element using encrypted messages.

## Features
1. Connects to a matrix homeserver and users.
2. Allow joining and creating rooms over matrix.
3. Encrypts and decrypts messages with a passphrase given betweeen users.

## Instalation and usage
First you have to clone the repository and install the needed libraries (IMPORTANT! to install matrix-nio --> pip install matrix-nio.
After setting the python environment you have to have all set your matrix environment to use the messenger client.
When running the program you will be asked yours matrix credentials then you can join a room server or create one. After that you can set passphrases for users to exchange ecrypted messages. Finally you can send and receive encrypted messages with the other users that will automatically decrypt by the program.

## The cipher used: "Medieval Cipher"
When given a english text the algorithm first normalizes, later the atbash cipher is applied and finally it uses passphrase as a key for Vigenère cipher. And reverse for decryption.

English Plaintext -> Normalize -> Atbash -> Vigenère

### I hope you find this helpful!
Javier Fernandez
Marta González 
