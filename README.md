# crypto
## All about Encryption and Decryption

### Some general info

#### Steps to follow or the general order of execution
* Generate the public and/or the private key
* Write the encryption/decryption logic using these keys
* Get the encrypted/decrypted message using these methods on entering an input message

#### How to generate your own private and public keys
* To generate a 2048-bit RSA private key, run the following command in cmd
`openssl genrsa -out private_key.pem 2048`
* This will generate a file using the openssl called private_key with the extension .pem in the current cmd directory which will contain a 2048-bit RSA key
* Now you will need to convert this .pem file to .der file in order to help java code to read the key from this file. Run the following command in cmd to do this
`openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt`
* This will convert the private key to PKCS8 format
* Now finally, generate the public key as well from the already generated private key in a java readable format. Run the following command in cmd to do this
`openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der`

#### All private keys have their specific public keys that are distributed to enable anyone to encrypt using it and someone holding the private key can decrypt the resulting encrypted message. As a result, in general, the private keys are given to less people than the number of people the public key is given to 
