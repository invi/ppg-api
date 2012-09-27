var createCmdReq = function(line, cmd_options) {
  var arg_options = cmd_options.args.concat([
    ["-h", "--help", "Shows this message"]
  ]);
  var req = {
    ts: Date.now(),
  };

  var parser = new optparse.OptionParser(arg_options);
  parser.banner = cmd_options.banner;
  parser.req = req;
  for (var i in cmd_options.on) {
    parser.on(i, cmd_options.on[i]);
  }
  parser.on("help", function(name, value) {
    Terminal.stdout.puts(parser.toString());
    req.help = true;
  });
  parser.parse(line);
  return parser.req;
}

var CommandParser  = {
  ExportPublic: function(line) {
    var options = {
      banner: 'Usage: ExportPublic [options]',
      args: [
        ["-k", "--keyid [keyid]", "Key to export"],
        ["-o", "--output [clipboard|file|keyserver]", "Optional output"],
      ],
      on: { 
        "keyid": function(name, value) {
           this.req.keyids = this.req.keyids || [];
           this.req.keyids.push(value);
        },
        "output": function(name, value) {
           this.req.output = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  ExportSecret: function(line) {
    var options = {
      banner: 'Usage: ExportSecret [options]',
      args: [
        ["-k", "--keyid [Key Id]", "Secret key to export"],
        ["-o", "--output [clipboard|file]", "Optional output"],
      ],
      on: { 
        "keyid": function(name, value) {
           this.req.keyid = this.req.keyid || [];
           this.req.keyid.push(value);
        },
        "output": function(name, value) {
           this.req.output = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  SaveFile: function(line) {
    var options = {
      banner: 'Usage: SaveFile [options]',
      args: [
        ["-t", "--text [Text]", "Text to save"],
      ],
      on: { 
        "text": function(name, value) {
           this.req.text = value.replace(/\\n/g, '\n');
           console.log(this.req.text);
        }
      }
    };
    return createCmdReq(line, options);
  },
  GenerateUserId: function(line) {
    var options = {
      banner: 'Usage: CenerateUserId [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-n", "--name [STRING]", "User Id name"],
        ["-e", "--expireseconds [NUMBER]", "Expiration time in seconds. 0 never"],
      ],
      on: { 
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "name": function(name, value) {
           this.req.options = this.req.options || {}
           this.req.options.name = value;
        },
        "expireseconds": function(name, value) {
           this.req.options = this.req.options || {}
           this.req.options.expireseconds = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  UpdateUserId: function(line) {
    var options = {
      banner: 'Usage: UpdateUserId [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-e", "--expireseconds [NUMBER]", "Expiration time in seconds. 0 never"],
        ["-u", "--userid [NUMBER]", "Index of User Id"],
      ],
      on: { 
        "expireseconds": function(name, value) {
           this.req.expireseconds = value;
        },
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "userid": function(name, value) {
           this.req.uid_num = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  GenerateSubkey: function(line) {
    var options = {
      banner: 'Usage: GenerateSubkey [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-e", "--expireseconds [NUMBER]", "Expiration time in seconds. 0 never"],
      ],
      on: { 
        "expireseconds": function(name, value) {
           this.req.options = this.req.options || {}
           this.req.options.expireseconds = value;
        },
        "keyid": function(name, value) {
           this.req.keyid = value;
        }
      }
    };
    return createCmdReq(line, options);
  },

  RevokeKey: function(line) {
    var options = {
      banner: 'Usage: GenerateSubkey [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-e", "--expireseconds [NUMBER]", "Expiration time in seconds. 0 never"],
        ["-r", "--reason [NUMBER]", "Revocation reason"],
        ["-c", "--comment [STRING]", "Revocation comment"],
      ],
      on: { 
        "expireseconds": function(name, value) {
           this.req.options = this.req.options || {}
           this.req.options.expireseconds = value;
        },
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "reason": function(name, value) {
           this.req.reason = value;
        },
        "comment": function(name,value) {
           this.req.comment = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  RevokeUserId: function(line) {
    var options = {
      banner: 'Usage: GenerateSubkey [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-e", "--expireseconds [NUMBER]", "Expiration time in seconds. 0 never"],
        ["-r", "--reason [NUMBER]", "Revocation reason"],
        ["-c", "--comment [STRING]", "Revocation comment"],
      ],
      on: { 
        "expireseconds": function(name, value) {
           this.req.options = this.req.options || {}
           this.req.options.expireseconds = value;
        },
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "reason": function(name, value) {
           this.req.reason = value;
        },
        "comment": function(name, value) {
           this.req.comment = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  RevokeSubkey: function(line) {
    var options = {
      banner: 'Usage: GenerateSubkey [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-e", "--expireseconds [NUMBER]", "Expiration time in seconds. 0 never"],
      ],
      on: { 
        "expireseconds": function(name, value) {
           this.req.options = this.req.options || {}
           this.req.options.expireseconds = value;
        },
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "reason": function(name, value) {
           this.req.reason = value;
        },
        "comment": function(name, value) {
           this.req.comment = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  SignUserId: function(line) {
    var options = {
      banner: 'Usage: GenerateSubkey [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key ID"],
        ["-u", "--userid [NUMBER]", "User Id position"],
      ],
      on: { 
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "userid": function(name, value) {
           this.req.uid_num = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  KeyserverSearch: function(line) {
    var options = {
      banner: 'Usage: KeyserverSearch [options]',
      args: [
        ["-t", "--text [STRING]", "Key ID or string to serach"],
      ],
      on: { 
        "text": function(name, value) {
           this.req.text = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  OptionsGet: function(line) {
    var options = {
      banner: 'Usage: OptionsGet [options]',
      args: [
        ["-h", "--help", "Shows this message"]
      ],
      on: { }
    };
    return createCmdReq(line, options);
  },
  OptionSet: function(line) {
    var options = {
      banner: 'Usage: OptionsGet [options]',
      args: [
        ["-h", "--help", "Shows this message"]
        ["-o", "--options", "Set options, syntax: options,value"]
      ],
      on: {
        "option": function(name, value) {
          console.log(name, value);
          req.option = value.split(",")[0];
          req.value = value.split(",")[1];
        }
      }
    };
    return createCmdReq(line, options);
  },
  ImportKey: function(line) {
    var options = {
      banner: 'Usage: ImportKey [options]',
      args: [
        ["-i", "--input [STRING]", "Posible values: file, text, clipboard, keyserver"],
        ["-t", "--text [STRING]", "When input is text, key data black"],
        ["-k", "--keyid [keyid]", "When input is keyserver, key to import from keyserver"],
      ],
      on: { 
        "input": function(name, value) {
           this.req.input = value;
        },
        "text": function(name, value) {
           this.req.text = value.replace(/\\n/g, '\n');
        },
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
      }
    };
    return createCmdReq(line, options);
  },
  GenerateKey: function(line) {
    var options = {
      banner: 'Usage: GenerateKey [options]',
      args: [
        ["-n", "--name [STRING]", "User Id name"],
        ["-t", "--type [NUMBER]", "Type of key to generate. 1 for RSA, 17 for DSA"],
        ["-st", "--subkeytype [NUMBER]", "Type of subkey to generate. 1 for RSA, 16 for ElGamal"],
      ],
      on: {
        "name": function(name, value) {
           this.req.name = value;
        },
        "type": function(name, value) {
          this.req.keyType = value;
        },
        "subkeytype": function(name, value) {
          this.req.subkeyType = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  RemoveKey: function(line) {
    var options = {
      banner: 'Usage: RemoveKey [options]',
      args: [
        ["-k", "--keyid [STRING]", "Key to remove"],
      ],
      on: {
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
      }
    };
    return createCmdReq(line, options);
  },
  Decrypt: function(line) {
    var options = {
      banner: 'Usage: Decrypt [options]',
      args: [
        ["-m", "--message [STRING]", "Message to decrypt"],
      ],
      on: {
        "message": function(name, value) {
           this.req.msg = value.replace(/\\n/g, '\n');
        },
      }
    };
    return createCmdReq(line, options);

  },
  Encrypt: function(line) {
    var options = {
      banner: 'Usage: Encrypt [options]',
      args: [
        ["-m", "--message [STRING]", "Message to encrypt"],
        ["-r", "--recipient [STRING]", "Key Id of recipient"],
        ["-s", "--sign [STRING]", "Key Id of secret signing key"]
      ],
      on: {
        "message": function(name, value) {
           this.req.msg = value.replace(/\\n/g, '\n');
        },
        "recipient": function(name, value) {
          this.req.enc_keyid = value;
        },
        "sign": function(name, value) {
          this.req.sign_keyid = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  Sign: function(line) {
    var options = {
      banner: 'Usage: Sign [options]',
      args: [
        ["-m", "--message [STRING]", "Message to encrypt"],
        ["-s", "--sign [STRING]", "Key Id of secret signing key"]
      ],
      on: {
        "message": function(name, value) {
           this.req.msg = value.replace(/\\n/g, '\n');
        },
        "sign": function(name, value) {
          this.req.keyid = value;
        }
      }
    };
    return createCmdReq(line, options);
  },
  Verify: function(line) {
    var options = {
      banner: 'Usage: Verify [options]',
      args: [
        ["-m", "--message [STRING]", "Message to verify"],
      ],
      on: {
        "message": function(name, value) {
           this.req.msg = value.replace(/\\n/g, '\n');
        },
      }
    };
    return createCmdReq(line, options);
  },
  GetPublicKeys: function(line) {
    var options = {
      banner: 'Usage: GetPublicKeys',
      args: [],
      on: {},
    };
    return createCmdReq(line, options);
  },
  GetSecretKeys: function(line) {
    var options = {
      banner: 'Usage: GetSecretKeys',
      args: [],
      on: {},
    };
    return createCmdReq(line, options);
  },
  RemoveSubkey: function(line) {
    var options = {
      banner: 'Usage: RemoveSubkey [options]',
      args: [
        ["-s", "--subkeyid [STRING]", "Subkey to remove"],
      ],
      on: {
        "subkeyid": function(name, value) {
           this.req.subkeyid = value;
        },
      }
    };
    return createCmdReq(line, options);
  },
  RemoveUserId: function(line) {
    var options = {
      banner: 'Usage: RemoveUserId [options]',
      args: [
        ["-k", "--keyid [STRING]", "Selected key"],
        ["-u", "--userid [NUMBER]", "User Id position"],
      ],
      on: {
        "keyid": function(name, value) {
           this.req.keyid = value;
        },
        "userid": function(name, value) {
           this.req.uid_num = value;
        },
      }
    };
    return createCmdReq(line, options);
  },
  help: function() {
    var req = {help: true};
    for (var i in this)
      Terminal.stdout.puts(i);
    return req;
  }
}
