## Pidgeon Privacy Guard API

Addon-SDK module of the OpenPGP protocol [RFC4880](http://tools.ietf.org/html/rfc4880) for Mozilla Firefox. 

### Requirements

* Mozilla Firefox 14.0 or newer.

### Features

#### Key pair generation

* RSA (1024/2048/4096 bits)
* DSA (1024 bits)
* ElGamal (1024 bits)

#### Supported asymmetric algorithms

* RSA encryption and signatures (1024/2048/4096 bits)
* DSA signatures (1024/2028/3072 bits)
* ElGamal encryption (1024/2048/3072 bits)

#### Tested symmetric algorithms

* Cast5
* AES-256

#### Compression algorightms (used for decompression)

* Zip
* Zlib
* Bzip2

### Use instructions

Clone the repository to the 'packages/ppg-api' in your Addon path and add to your `package.json` file the following:

   ...,`
   "dependencies": ["addon-kit","api-utils","ppg-api"],
   "packages": "./packages/ppg-api"
   ...,

Then include `var {ppgapp} = require('ppgapp')` to use the module.

