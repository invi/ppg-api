const {ppgapp} = require('ppgapp');
const {filePicker, saveFilePicker} = require('util/filepicker');
const {storage} = require('ring/storage');
let clipboard = require("clipboard");
const logger = require('util/logger').create("worker_messages.js");
const keyserver = require('util/hkp');
const {getStr} = require("util/lang");
const file = require('file');

var worker_messages = {
  workers: [],

  subscribe: function(worker){
    var self = this;
    logger.debug("Subscribe woker:" + worker);
    this.workers.push(worker);
   
// ## request: ppgExportPublic 
// ## response: ppgExportPublicRes
//
// Export multiple keys in base64 armored format to the specified output
//
// Required request parameters:
//   req = { 
//            keyids: array of keyids,
//            output: ["clipboard"|"file"|"keyserver"],
//   }
//
// Response: 
//   res = {
//            rc: integer 0 if OK
//            data: expedted returned data
//   }
    worker.port.on("ppgExportPublic", function(req) {
      var {ts, keyids, output} = req;
      var res = {ts: ts, keyids: keyids, output: output, rc: 0, data: null};
      try {
        var exportdata = ppgapp.exportPublic(keyids);
        switch(output) {
          case "clipboard":
            clipboard.set(exportdata);
            res.data = "Copied to clipboard!";
            break;
          case "file":
            var filename = saveFilePicker().path;
            if (filename) {
              var stream = file.open(filename, "w");
              if (stream) {
                stream.write(exportdata);
                stream.close();
                res.data = "Exported to file " + filename;
              }
              else 
                res.data = "Open file " + filename + " failed";
            } else {
              res.data = "Export cancelled!";
            }
            break;
          case "keyserver":
            throw Error("Export key server not implemented.");
          default: 
            res.data = exportdata;
        }
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgExportPublicRes", res);
    });

    worker.port.on("ppgExportSecret", function(req) {
      var {ts, keyid, output} = req;
      var res = {ts: ts, keyid: keyid, output: output, rc: 0, data: null};
      try { 
        var exportdata = ppgapp.exportSecret(keyid);
        switch(output) {
          case "clipboard":
            res.data = "Copied to clipboard!";
            break;
          case "file":
            var filename = saveFilePicker().path;
            if (filename) {
              var stream = file.open(filename, "w");
              if (stream) {
                stream.write(exportdata);
                stream.close();
                res.data = "Exported to file " + filename;
              }
              else 
                res.data = "Open file " + filename + " failed";
            } else {
              res.data = "Export cancelled!";
            }
            break;
          default: 
            res.data = keydata;
        }
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgExportSecretRes", res);
    });

    worker.port.on("ppgSaveFile", function(req) {
      var {ts, text} = req;
      var res = {ts: ts, rc: 0, data: null};
      try {
        var filename = saveFilePicker().path;
        if (filename) {
          var stream = file.open(filename, "w");
          stream.write(text);
          stream.close();
          res.data = filename;
        } else {
          res.rc = -1;
          res.data = "Save to file cancelled!";
        }
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgSaveFileRes", res);
    });

    worker.port.on("ppgSetClipboard", function(req) {
      var {ts, text} = req;
      var res = {ts: ts, text: text, rc: 0, data: null}
      try {
        clipboard.set(text);  
        res.data = "Exported to clipboard";
      } catch(err) {
        res.rc = -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgSetClipboardRes", res);
    });

    worker.port.on("ppgGenerateUserId", function(req) {
      var res = {rc: 0, data: null};
      var {keyid, options} = req;
      ppgapp.generateUserId(keyid, options, function(err, key, uid) {
        if (err) {
          res.rc = -1;
          res.msg = err.toString();
        } else {
          res.msg = "Create User Id " + uid.name;
          res.key = key;
          res.uid = uid;
        }
        worker.port.emit("ppgGenerateUserIdRes", res);
      });
    });

    worker.port.on("ppgUpdateUserId", function(req) {
      var {ts, uid_num, keyid, expireseconds} = req;
      var res = {ts: ts, rc: 0, uid_num: uid_num, data: null};
      ppgapp.editUserId(keyid, uid_num, expireseconds, 
        function(err, key, uid) {
          if (err) {
            res.rc = -1;
            res.data = "Copied to clipboard!";
            res.msg = err.toString();
          } else {
            res.key = key;
            res.uid = uid;
          }
          worker.port.emit("ppgUpdateUserIdRes", res);
        }
      );
    });

    worker.port.on("ppgGenerateSubkey", function(req) {
      var {ts, keyid, options} = req;
      var res = {ts: ts, rc: 0, data: null, key: null, subkey: null};
      ppgapp.generateSubkey(keyid, options, function(err, key, subkey) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = err.toString();
        } else {
          res.key = key;
          res.subkey = subkey;
          res.data = "Generated subkey " + subkey.id;
        }
        worker.port.emit("ppgGenerateSubkeyRes", res);
      });
    });

    worker.port.on("ppgRevokeKey", function(req) {
      var {ts, keyid, reason, comment} = req;
      var res = {ts: ts, keyid: keyid, rc: 0, data: null, key: null};
      ppgapp.revokeKey(keyid, reason, comment, function(err, key) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = err.toString();
        } else {
          res.key = key;
          res.data = "Key Revoked: keyid=" + key.id;
        }
        worker.port.emit("ppgRevokeKeyRes", res);
      });
    });

    worker.port.on("ppgRevokeUserId", function(req) {
      var {ts, keyid, reason, comment, uid_index} = req;
      var res = {rc:0, keyid:req.keyid, key: null, uid: null};
      ppgapp.revokeUserId(keyid, uid_index, reason, comment, function(err, key, uid) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = err.toString();
        } else {
          res.data = "Key Revoked: keyid=" + key.id;
        }
        worker.port.emit("ppgRevokeUserIdRes", res);
      });
    });

    worker.port.on("ppgRevokeSubkey", function(req) {
      var {ts, subkeyid, reason, comment} = req;
      var res = {ts: ts, rc:0, subkeyid: subkeyid, reason: null, comment: null, data: null};
      ppgapp.revokeSubkey(subkeyid, reason, comment, function(err, key, subkey) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = err.toString();
        } else {
          res.key = key;
          res.subkey = subkey;
          res.data = "Subkey revoked: keyid=" + subkey.id;
        }
        worker.port.emit("ppgRevokeSubkeyRes", res);
      });
    });

    worker.port.on("ppgSignUserId", function(req) {
      var {ts, keyid, uid_num} = req;
      var res = {ts: ts, rc: 0, data: null};
      ppgapp.signUserId(keyid_str, uid_name, function(err, key, uid, sig) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = "Could't sign user id";
        } else {
          res.key = key;
          res.uid = uid;
          res.sig = sig;
        }
        worker.port.emit("ppgSignUserIdRes", res);
      });
    });

    worker.port.on("ppgKeyserverSearch", function(req) {
      var {ts, text} = req;
      var res = {rc: 0, ts: ts, keys: null, data: null};
      var ks = new keyserver.KeyServer(storage.get_option("keyserver"));
      ks.search(text, function (err, serverkeys) {
        if (err) {
          res.rc = "-1";
          res.data = err.toString();
        } else 
          res.keys = serverkeys;
        worker.port.emit("ppgKeyserverSearchRes", res);
      });
    });

    worker.port.on("ppgOptionsGet", function(req) {
      var {ts} = req;
      var res = {ts: ts, rc: 0, options: null, data: null}
      try {
        res.options = storage.get_all_options()
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgOptionsGetRes", res);
    });

    worker.port.on("ppgOptionSet", function(req) {
      var {ts, option, value} = req;
      var res = {ts: ts, rc: 0, data: null};
      try {
        storage.set_option(option, value);
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgOptionSetRes", res);
    });
  
    worker.port.on("ppgImportKey", function(req) {
      var {ts, input, keyids, text} = req;
      var res = {ts: ts, rc: 0, data: null, keys: []};
      try {
        switch(input) {
          case "file":
            if (pickedfile = filePicker()) {
              var keydata = file.read(pickedfile.path);
              res.data = getStr("fromfile") + pickedfile.path;
              ppgapp.importData(keydata, function(formatted_key) {
                if (formatted_key == null) {
                  worker.port.emit("ppgImportKeyRes", res);
                } else {
                  res.keys.push(formatted_key);
                }
              });
            } else {
              res.rc = "-5";
              res.data = getStr("selcancel");
              worker.port.emit("ppgImportKeyRes", res);
            }
            break;
          case "text":
            ppgapp.importData(text, function(formatted_key) {
              if (formatted_key == null) {
                worker.port.emit("ppgImportKeyRes", response);
              } else {
                res.keys.push(formatted_key);
              }
            });
            break;
          case "clipboard":
            var keydata = clipboard.get();
            ppgapp.importData(keydata, function(formatted_key) {
              if (formatted_key == null) {
                worker.port.emit("ppgImportKeyRes", res);
              } else {
                res.keys.push(formatted_key);
              }
            });
            break;
          case "keyserver":
            var ks = new keyserver.KeyServer(storage.get_option("keyserver"));
            var count = 0;
            for (var i=0; i<keyids.length; i++) {
              ks.get(keyids[i], function (err, keydata) {            
                if (err==null) {
                  res.data = "Imported from keyserver";
                  ppgapp.importData(keydata, function(formatted_key) {
                    if (formatted_key) {
                      count++;
                      res.keys.push(formatted_key);
                    } else if (count == keyids.length) {
                      worker.port.emit("ppgImportKeyRes", res);
                    }
                  });
                } else {
                  count++;
                  res.rc = "-3";
                  res.data = err.toString();
                  if (count == keyids.length)
                    worker.port.emit("ppgImportKeyRes", res);
                }
              });
            }
            break;
          default:
            res.rc = "-4";
            res.data = "ERROR: unknow importing source";
            worker.port.emit("ppgImportKeyRes", res);
        }
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
        worker.port.emit("ppgImportKeyRes", res);
      }
    });
  
    worker.port.on("ppgGenerateKey", function(req) {
      var {ts, ts} = req;
      var res = {ts: ts, rc: 0};
      ppgapp.generateKeypair(req, function(err, key) {
        if (err) {
          res.rc = err.rc || -1;
          res.msg = err.toString();
        } else {
          res.key = key;
          res.msg = getStr("generated", key.id);
        }
        worker.port.emit("ppgGenerateKeyRes", res);
      });
    });
  
    worker.port.on("ppgRemoveKey", function(req) {
      var {ts, keyid} = req;
      var res = {ts: ts, rc: 0, data: null};
      try {
        var keys = ppgapp.removeKey(keyid);
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgRemoveKeyRes", res);
    });

    worker.port.on("ppgDecrypt", function(req) {
      var {ts, msg} = req;
      var res = {ts: ts, rc: 0, enc_keyid: null, data: null, type: null};
      ppgapp.decrypt(msg, function(err, decmsg, enc_keyid) {
        res.enc_keyid = enc_keyid;
        if (err) {
          res.rc = -1;
          res.msg = err.toString();
        } else {
          res.type = decmsg.type; 
          res.msg = decmsg.msg; 
          res.sign_keyid = decmsg.sign_keyid;
        }
        worker.port.emit("ppgDecryptRes", res);
      });
    });

    worker.port.on("ppgEncrypt", function(req) {
      var {ts, enc_keyid, sign_keyid, msg} = req;
      var res = {rc: 0, ts: ts, enc_keyid: enc_keyid, sign_keyid: sign_keyid, data: null};
      ppgapp.encrypt(msg, [enc_keyid], sign_keyid, function(err, data) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = err.toString();
        } else {
          res.data = data;
        }
        worker.port.emit("ppgEncryptRes", res);
      });
    });

    worker.port.on("ppgSign", function(req) {
      var {ts, keyid, msg} = req;
      var res = {rc: 0, ts: ts, keyid: keyid};
      ppgapp.sign(msg, keyid, function(err, signedData) {
        if (err) {
          res.rc = err.rc || -1;
          res.data = err.toString();
        } else {
          res.data = signedData;
        }
        worker.port.emit("ppgSignRes", res);
      });
    });

    worker.port.on("ppgVerify", function(req) {
      var {ts, msg} = req;
      var res = {rc: 0, ts: ts, valid: false, keyid: null};
      ppgapp.verify(msg, function(err, valid, issuerKeyId) {
        res.issuerKeyId = issuerKeyId;
        if (err) {
          res.rc = err.rc || -1
        } else {
          res.valid = valid;
        }
        worker.port.emit("ppgVerifyRes", res);
      });
    });

    worker.port.on("ppgGetPublicKeys", function(req) {
      var {ts} = req;
      var res = {ts: ts, rc: 0, keys: null, data: null}
      try {
        res.keys = storage.getPublicKeys();
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgGetPublicKeysRes", res);
    });

    worker.port.on("ppgGetKeys", function() {
      var keys = storage.getAllKeys();
      worker.port.emit("ppgGetKeysRes", keys);
    });

    worker.port.on("ppgGetSecretKeys", function(req) {
      var {ts} = req;
      var res = {ts: ts, rc: 0, keys: null, data: null}
      try {
        res.keys = storage.getPrivateKeys();
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgGetSecretKeysRes",  res);
    });

    worker.port.on("ppgRemoveSubkey", function (req) {
      var {ts, subkeyid} = req;
      var res = {ts: ts, rc: 0, data: null, subkeyid: null};

      try {
        var removed = ppgapp.removeSubkey(subkeyid);
        if (removed) {
          res.data = "Subkey " + subkeyid + "removed!";
          res.subkeyid = subkeyid;
        } else {
          res.rc = -1;
          res.data = "Couldn't remove subkey " + subkeyid + "";
        }
      } catch(err) {
        res.rc = err.rc || -1;
        res.data = err.toString();
      }
      worker.port.emit("ppgRemoveSubkeyRes", res);
    });

    worker.port.on("ppgRemoveUserId", function (req) {
      var {ts, keyid, uid_num} = req;
      var res = {ts: ts, rc: 0, data: null, keyid: keyid, uid_num: uid_num};
      if (ppgapp.removeUserId(keyid, uid_num)) {
        res.data = "Uid[" + uid_num + "] removed!";
      } else {
        res.rc = -1;
        res.data = "Couldn't remove uid[" + uid_num + "]";
      }
      worker.port.emit("ppgRemoveUserIdRes", res);
    });
  },

  unsubscribe: function(worker) {
    logger.debug("Unsubscribe woker: ", worker);
    for (var i=0; i<this.workers.length; i++) {
      if (workers[i] == worker) {
        delete(workers[i]);
        return;
      }
    }
  }
}

exports.worker_messages = worker_messages;


