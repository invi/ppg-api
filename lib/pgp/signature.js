// # Signature.js
// 
//     Stability: 2 - Unstable
//
// Module that represents any kind of signature to be loaded or generated.
//

const PGP = require('pgp/openpgpdefs.js');
const logger = require('util/logger').create("signature.js");
const misc = require('util/misc.js');
const asymcrypto = require("crypto/asym");
const base64Decode = require("api-utils/base64").decode;
const base64Encode = require("api-utils/base64").encode;
const {hashData} = require("crypto/hash");
const {write_packet_header} = require("pgp/export");
const {getStr} = require('util/lang');
const {Trait} = require('light-traits');
const {BaseTrait} = require('pgp/base-trait');
const {FormatTrait} = require('pgp/format-trait');


// ## Helpers
//
// ### Checks status of the signature with the Public Key
// 
// Function to be used 
function _do_check_messages(kb, sig) {
  var cur_time;
  var pk = kb.kpkt;

  if( pk.timestamp > sig.timestamp )
  {
	  d = pk.timestamp - sig.timestamp;
    logger.error(d==1 ? "public key %s is %lu second newer than the signature"
	                    : "public key %s is %lu seconds newer than the signature",
	                      kb.getKeyIDStr(), d);

	  return PGP.ERR.TIME_CONFLICT; /* pubkey newer than signature */
  }

  cur_time = parseInt(new Date().getTime() / 1000);

  if( pk.timestamp > cur_time )
  {
    d = pk.timestamp - cur_time;
    logger.error( d==1 ? "key %s was created %lu second\
  	                     in the future (time warp or clock problem)"
  	                   : "key %s was created %lu seconds\
	                       in the future (time warp or clock problem)",
                         kb.getKeyIDStr(),d );
    return PGP.ERR.TIME_CONFLICT;
  }

  if( pk.has_expired || (pk.expiredate && pk.expiredate < cur_time)) 
  {
    logger.info("NOTE: signature key %s expired %s",
                kb.getKeyIDStr(), 
                new Date(pk.expiredate * 1000));
    pk.has_expired = true;
  }

  if (pk.flags.revoked)
  {
	  logger.info("NOTE: signature key %s has been revoked",
                pk.getKeyIDStr());
  }
  return 0;
}

// ### write_sigsubpkt
//
// Wraps signature subpacket with encoded length.
//
// TODO: Missing long length encodings.
function write_sigsubpkt(type, str) {
  return String.fromCharCode(str.length + 1) + 
         String.fromCharCode(type) + str;
}

// ### write_sig_unhash
//
// Writes signature unhashed issuer subpacket.
//
function write_sig_unhash(sig) {
  return misc.stoa(write_sigsubpkt(PGP.SIGSUBPKT.ISSUER, sig.pkt.keyid));
}

// ### write_sig_hash
//
// Writes signature hashed sigunature subpackets, according to the Signature created.
//
function write_sig_hash(sig) {
  var ret;
  switch(sig.pkt.sig_class) {
    case PGP.SIGCLASS.KEY_SIG:
    var expireseconds = sig.pkt.expiredate - sig.pkt.timestamp;
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    ret += misc.atos([2,27,3]);
    ret += write_sigsubpkt(PGP.SIGSUBPKT.SIG_EXPIRE, misc.u32_to_string(expireseconds));
    ret += misc.atos([6,11,9,8,7,3,2,6,21,8,2,9,10,11,4,22,2,3,1,2,30,1,2,23,128]);
    break;

    case PGP.SIGCLASS.SUBKEY_SIG:
    var expireseconds = sig.pkt.expiredate - sig.pkt.timestamp;
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp)) +
          write_sigsubpkt(PGP.SIGSUBPKT.KEY_FLAGS, String.fromCharCode(12)) +
          write_sigsubpkt(PGP.SIGSUBPKT.SIG_EXPIRE, misc.u32_to_string(expireseconds));
    break;

    case PGP.SIGCLASS.CANONICAL:
    case PGP.SIGCLASS.BINARY:
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    break;

    case PGP.SIGCLASS.KEY_REV:
    case PGP.SIGCLASS.SUBKEY_REV:
    case PGP.SIGCLASS.UID_REV:
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    var revoc_subpacket = String.fromCharCode(sig.pkt.revoc_reason) + sig.pkt.revoc_comment;
    ret += write_sigsubpkt(PGP.SIGSUBPKT.REVOC_REASON, revoc_subpacket);
    ret += write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    //ret += write_sigsubpkt(PGP.SIGSUBPKT.ISSUER, sig.keyid);
    break;

    case PGP.SIGCLASS.UID_SIG:
    ret = write_sigsubpkt(PGP.SIGSUBPKT.SIG_CREATED, misc.u32_to_string(sig.pkt.timestamp));
    ret += write_sigsubpkt(PGP.SIGSUBPKT.ISSUER, sig.pkt.keyid);
    break;

    default:
    throw new Error("PGP.ERR.BAD_SIGCLASS");
  }
  return misc.stoa(ret);
}

// ## Class: Signature
// 
// Creates an instance of Signature.
//
// To generate a new signature or to load a stored signature, refer to Signature.generate and
// Signature.load static methods.
function Signature() {
  var sig = Trait.compose(BaseTrait, FormatTrait).create(Signature.prototype);
  sig.key = null;
  sig.holdingkey = null;
  sig._sig = {
    pkt: { pkttype: PGP.PKT.SIGNATURE, data: [], version: 4 },
    revsigs: [],
  }
  sig.status = {
    valid: false, 
    verified: false, 
    revoked: false
  };
  return sig;
}

// ### Signature.load
// 
// Creates an instance of Signature.
//
// `_sig` signature object data.
//
// `holdingkey` Is the `Key` object to which the signature is attached.
//
// `verified` When loading from storage must be set to true, since is considered as a verified signature.
Signature.load = function(_sig, holdingkey, verified) {
  var sig = new Signature();
  try {
    sig._sig = _sig;
    sig.holdingkey = holdingkey;
    if (sig.isSelf()) sig.key = holdingkey;
    if (verified == true) sig.status.valid = true;
  } catch(err) {
    logger.error(err);
  } 
  return sig;
}

// ### Signature.generate.
// 
// Generates an Signature instance.
//
// `pars` signature object data.
//
// `callback` Callback function. First argument represents the error, which has a `null` value when success, otherwise
// `Error object` is returned. Second argument is a `Signature object` when success.
Signature.generate = function(pars, callback) {
  try {
    var ts = Math.floor(Date.now() / 1000); 
    var sig = new Signature();
    sig._sig.pkt.sig_class = pars.sig_class;
    sig._sig.pkt.digest_algo = PGP.HASH.SHA1;
    sig._sig.pkt.revoc_reason = pars.revoc_reason;
    sig._sig.pkt.revoc_comment = pars.revoc_comment;
    sig._sig.pkt.flags = {"exportable":1, "revocable":1};
    sig._sig.pkt.keyid = pars.key.getKeyId();
    sig._sig.pkt.timestamp = pars.timestamp || ts;
    sig._sig.pkt.expireseconds = pars.expireseconds || 0;
    sig._sig.pkt.expiredate = pars.expiredate;
    sig._sig.pkt.pubkey_algo = pars.key.getAlgo(),
    sig._sig.pkt.hashed = {};
    sig._sig.pkt.hashed.data = write_sig_hash(sig._sig);
    sig._sig.pkt.unhashed = {};
    sig._sig.pkt.unhashed.data = write_sig_unhash(sig._sig);

    sig.key = pars.key;
    sig.holdingkey = pars.holdingkey || pars.key;

    sig.logger = logger;
    sig.signData(pars.data, function(err) {
      if (err) callback(err);
      else callback(null, sig);
    });
  } catch(err) { logger.error(err) };
}

// ### Signature.prototype.isNonSelf 
//
// `returns` True if this isn't a user id self-signature.
//
Signature.prototype.isNonSelf = function() {
  return this.holdingkey.getKeyId() != this.getKeyId();
};

/**
 * @return {boolean} True if this is a user id self-signature
 */
Signature.prototype.isUserIdSig = function() {
  return ((this._sig.pkt.sig_class & ~3) == PGP.SIGCLASS.UID_SIG);
};

/**
 * @return {boolean} True if this is a user id self-signature
 */
Signature.prototype.isCertSig = function() {
  return (((this._sig.pkt.sig_class & ~3) == PGP.SIGCLASS.UID_SIG) || 
            this._sig.pkt.sig_class == PGP.SIGCLASS.DIRECT_SIG);
};

/**
 * @return {boolean} True if this is a user id revocation signature
 */
Signature.prototype.isUserIdRev = function() {
  return (this._sig.pkt.sig_class == PGP.SIGCLASS.UID_REV);
};

/**
 * @return {boolean} True if this is key signature
 */
Signature.prototype.isKeySig = function() {
  return (this._sig.pkt.sig_class == PGP.SIGCLASS.KEY_SIG);
};

/**
 * @return {boolean} True if this is subkey signature
 */
Signature.prototype.isSubkeySig = function() {
  return (this._sig.pkt.sig_class == PGP.SIGCLASS.SUBKEY_SIG);
};

/**
 * @return {boolean} True if this is subkey revocation signature
 */
//Signature.prototype.isSubkeyRev= function() {
//  return (this._sig.sig_class == PGP.SIGCLASS.SUBKEY_REV);
//};

/**
 * @return {boolean} True if this is key revocation signature
 */
Signature.prototype.isKeyRev = function() {
  return ((this._sig.pkt.sig_class == PGP.SIGCLASS.KEY_REV) ||
           this._sig.pkt.sig_class == PGP.SIGCLASS.SUBKEY_REV);
};

/**
 * @returns {boolean} True if this is a user id self-signature.
 */
Signature.prototype.isSelf = function() {
  return this.getKeyId() == this.holdingkey.getKeyId();
};

/**
 * @returns {string} Return Key id string data.
 */
Signature.prototype.getKeyId = function() {
  return this._sig.pkt.keyid;
};

/**
 * @returns {number} Packet type
 */
Signature.prototype.getPacketType = function() {
  return this._sig.pkt.pkttype;
};

/**
 * @returns {object} Signature serializable data
 */
Signature.prototype.getPacket = function() {
  return this._sig.pkt;
}


/**
 * Sets signature raw data value
 * @param {string} sigdata  Data string
 */
Signature.prototype.setData = function(sigdata) {
  if (this.key.getAlgo() == PGP.PUBKEY.ALGO.DSA) {
    var d1 = sigdata.substr(0, sigdata.length / 2);
    var d2 = sigdata.substr(sigdata.length / 2);
    this._sig.pkt.data[0] = misc.addmpi_len(d1);
    this._sig.pkt.data[1] = misc.addmpi_len(d2);
  } else {
    var len = sigdata.length;
    len *= 8; //in bits
    this._sig.pkt.data[0] = misc.atos([len >> 8, len & 0xff ]);
    this._sig.pkt.data[0] += sigdata;
  }
}

/**
 * Sets signature digest start
 * @param {array} digest_start Two first hash values as byte array 
 */
Signature.prototype.setDigestStart = function(digest_start) {
  this._sig.pkt.digest_start = digest_start;
}

/**
 * Performs a signature of the data and this signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @param {function} crypto_fnc Assymetric crypto function
 * @param {string} data Data string to sign
 * @param {function} callback Callback after signing
 */
Signature.prototype.signData = function(data, callback) {
  var self = this;
  var md = data + this.getDigest();
  var key = this.key;
  logger.debug("Issuer key: " + this.key.getKeyIdStr());
  logger.debug("Holding key: " + this.getKeyId());
  asymcrypto.sign(this._sig.pkt.digest_algo, key.getAlgo(), key.getPubKey(), key.getSecKey(),
              key.getSki(), md, function(hashed_md, sigdata) {
                try  { 
                  self.setDigestStart([hashed_md.charCodeAt(0), 
                                       hashed_md.charCodeAt(1)]);
                  self.status.valid = true;
                  self.status.verified = true;
                  self.setData(sigdata);
                  callback(null);
                } catch(err) {
                  callback(err);
                }
              });
}


/**
 * Performs a hash of the key and signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @returns {string} Hashed data string
 */
Signature.prototype.hash = function(cipher_fnc) {
  var md = this.key.getDigest() + this.getDigest(); 

  //XXX cipher
  var hashed_md = cipher_fnc(misc.stoa(md));

  //unhashed sig
  this.setDigestStart([hashed_md.charCodeAt(0), 
                       hashed_md.charCodeAt(1)]);

  var oid = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
  return misc.atos(oid) + hashed_md;
}

/**
 * Performs a hash of the data argument and signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @param {string} data Data to hash
 * @returns {string} Hashed data string
 */
Signature.prototype.hashData = function(data) {
  var md = data + this.getDigest();

  //XXX cipher
  var hashed_md = hashData(this._sig.digest_algo, md);

  ////unhashed sig
  this.setDigestStart([hashed_md.charCodeAt(0), 
                       hashed_md.charCodeAt(1)]);

  var oid = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
  return misc.atos(oid) + hashed_md;
}

/**
 * Generates the message digest for the signature 
 *
 * @returns {string} Message digest string data
 */
Signature.prototype.getDigest = function() {
  var md = "", n = 0, pkt = this._sig.pkt;

  md += String.fromCharCode(pkt.version) +
        String.fromCharCode(pkt.sig_class) +
        String.fromCharCode(pkt.pubkey_algo) +
        String.fromCharCode(pkt.digest_algo);

  if (pkt.hashed) {
    n = pkt.hashed.data.length;
    md += misc.u16_to_string(n);
    md += misc.atos(pkt.hashed.data);
    n += 6;
  } else {
	  /* Two octets for the (empty) length of the hashed
             section. */
    //XXX not used
    md += String.fromCharCode(0);
    md += String.fromCharCode(0);
	  n = 6;
	}
 	/* add some magic */
  md += String.fromCharCode(pkt.version) +
        String.fromCharCode(0xff) +
        misc.u32_to_string(n);

  return md;
}

/**
 * Performs a verification of the data and this signature
 *
 * @param {function} cipher_fnc Cipher hash function
 * @param {function} crypto_fnc Assymetric crypto function
 * @param {string} data Data string to sign
 * @param {function} callback Callback after signing
 */
Signature.prototype.verifyData = function(data, callback) {
  try {
    var self = this;
    var md = data + this.getDigest();
    asymcrypto.verify(this.key.getAlgo(), this._sig.pkt.digest_algo, this._sig.pkt.data, 
                  this.key.getPubKey(), md, function(isValid) {
      try  { 
        self.status.valid = isValid;
        self.status.verified = true;
        callback(null, isValid);
      } catch(err) { callback(err);}
    });
  } catch(err) { callback(err) };
}

/**
 * Performs a verification of the key and signature
 *
 * @param {function} cipher Initialized crypto module
 * @param {function} callback Callback after signing
 */
Signature.prototype.verify = function(callback) {
  this.verifyData(this.key.getDigest(), callback);
}

/**
 * @returns {boolean} True if signature is valid
 */
Signature.prototype.isValid = function() {
  return this.status.valid;
}

/**
 * @returns {object} Signature serializable data
 */
Signature.prototype.serialize = function() {
  return this._sig.pkt;
}


Signature.prototype.hasEncryptionFlag = function() {
  return this.getKeyFlags() & (PGP.KEY_FLAGS.CS | PGP.KEY_FLAGS.EC); 
}

Signature.prototype.getIssuerKeyId = function() {
  return this._sig.pkt.keyid;
}

Signature.prototype.getIssuerKeyIdStr = function() {
  return misc.stohex(this._sig.pkt.keyid).toUpperCase();
}

Signature.prototype.getSigClassStr = function() {
  return PGP.SIGCLASS_STR[this._sig.pkt.sig_class];
}

Signature.prototype.getFormatted = function() {
  return this.getFormattedPacket();
}

Signature.prototype.getRevocReasonStr = function() {
  var {revoc_reason} = this._sig.pkt
  switch(revoc_reason) {
    case 0:
      return getStr("rev0x00");
    case 1:
    case 2:
    case 3:
      if (this.isKeyRev()) 
        return getStr("rev0x" + ("0" + revoc_reason.toString(16).slice(-2)))
      return getStr("invalidKeyRevReason");
    case 32:
      if (this.isUserIdRev())
        return getStr("rev0x20");
      return getStr("invalidCertRevReason");
    default:
      if (revoc_reason >= 100 && revoc_reason <= 110) 
        return getStr("rev0x64");
      return getStr("unkownRevReason");
  }
}

Signature.prototype.getFormattedPacket = function() {
  var sig = {
    id: this.getIssuerKeyIdStr(),
    sig_class: this.getSigClassStr(),
    revoked: this.isRevoked(),
    expired: this.isExpired(),
    verified: this.isVerified(),
    keyflags: this.getKeyFlagsStr(),
    hash_algos: this.getHashAlgosStr(),
    sym_algos: this.getSymAlgosStr(),
    revoc_reason_str: this.getRevocReasonStr(),
    revoc_comment: this._sig.pkt.revoc_comment,
    creation_date : this.getCreationDate(),
    expiration_date: this.getExpirationDate(),
    ringstatus: this.status.ringstatus,
    valid: this.isValid(),
  }
  return sig;
}

Signature.prototype.isExpired = function() {
  if (this.getPacket().timestamp == this.getPacket().expiredate) {
    return false;
  } else {
    var ts = Math.ceil(new Date().getTime()/1000);
    var expiredate = this.getPacket().expiredate;
    return !!(expiredate && (ts > expiredate));
  }
}

Signature.prototype.getKeyFlags = function() {
  return this._sig.pkt.key_flags;
}

Signature.prototype.getKeyFlagsStr = function() {
  var flags = this.getKeyFlags();
  var ret = [];
  if (flags & PGP.KEY_FLAGS.CS) ret.push(getStr("keyFlag0x01"));
  if (flags & PGP.KEY_FLAGS.SD) ret.push(getStr("keyFlag0x02"));
  if (flags & PGP.KEY_FLAGS.EC) ret.push(getStr("keyFlag0x04"));
  if (flags & PGP.KEY_FLAGS.ES) ret.push(getStr("keyFlag0x08"));
  if (flags & PGP.KEY_FLAGS.SM) ret.push(getStr("keyFlag0x10"));
  if (flags & PGP.KEY_FLAGS.AU) ret.push(getStr("keyFlag0x20"));
  if (flags & PGP.KEY_FLAGS.MP) ret.push(getStr("keyFlag0x80"));
  return ret;
}

Signature.prototype.getHashAlgos = function() {
  return this._sig.pkt.pref_hash || [];
}

Signature.prototype.getHashAlgosStr = function() {
  var hashes = this.getHashAlgos();
  var ret = [];
  for (var i=0;i<hashes.length;i++) {
    if (hashes[i] in PGP.HASH_INV) 
      ret.push(PGP.HASH_INV[hashes[i]]);
    else
      ret.push(getStr("unknownHashAlgo", hashes[i]))
  }
  return ret;
}

Signature.prototype.getSymAlgos = function() {
  return this._sig.pkt.pref_sym || [];
}

Signature.prototype.getSymAlgosStr = function() {
  var symalgos = this.getSymAlgos();
  var ret = [];
  for (var i=0;i<symalgos.length;i++) {
    if (symalgos[i] in PGP.CIPHER.ALGO_INV) 
      ret.push(PGP.CIPHER.ALGO_INV[symalgos[i]]);
    else
      ret.push(getStr("unknownHashAlgo", symalgos[i]))
  }
  return ret;
}

/**
 * @function
 * @returns {string} Binary data string of the signature packet 
 */
Signature.prototype.write_packet = function() {
  var ret = "",
      sigPacket = this.getPacket();
  
  ret += String.fromCharCode(sigPacket.version);
  ret += String.fromCharCode(sigPacket.sig_class); 
  ret += String.fromCharCode(sigPacket.pubkey_algo); 
  ret += String.fromCharCode(sigPacket.digest_algo) ;
  ret += misc.u16_to_string(sigPacket.hashed.data.length); 
  ret += misc.atos(sigPacket.hashed.data); 
  ret += misc.u16_to_string(sigPacket.unhashed.data.length);
  ret += misc.atos(sigPacket.unhashed.data); 
  ret += misc.atos(sigPacket.digest_start); 

  for (var i=0;i<sigPacket.data.length;i++) 
    ret += sigPacket.data[i];

  return misc.write_packet_header(this.getPacketType(), ret.length) + ret;
}

exports.Signature = Signature;
