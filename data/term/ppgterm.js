
var _parser = new optparse.OptionParser([]);
_parser.on(0, function(cmd) {
  _parser.command = cmd;
});

function parseCommand(line) {
  var aStr = line.match(/(-*)\w+|"[^"]+"/g) || [];
  var i = aStr.length;
  while(i--){
    aStr[i] = aStr[i].replace(/"/g,"");
  }
  _parser.parse(aStr);
  var cmd = _parser.command || "";
  var found = false;
  for (var i in CommandParser) {
    if (i == cmd) {
      found = true;
      break;
    }
  }
  if (!found) 
    throw Error("Command " + cmd + " not found");

  var req = CommandParser[cmd](aStr);
  return {command: cmd, req: req};
}

Terminal.commandCallBack=function(line, callback){

  try{
    if(line.match(/^[ ]*\</)) {
      Terminal.stdout.write(line);
    } else {
      var {command, req} = parseCommand(line);
      if (req.help) { 
        callback();
        return
      };
      self.port.once("ppg" + command + "Res", function(res) {
        try {
          Terminal.stdout.puts(JSON.stringify(res, null, '  '));
          callback();
        } catch(err) {
          console.log(err, err.lineNumber, err.fileName);
        }
      });
      self.port.emit("ppg" + command, req);
    }      
  } catch(err) {
    Terminal.stdout.puts(err.toString());
    callback();
  }

};

Terminal.header="\n### PidgeonPG Terminal ###\n\nType 'help' to list the available commands. To see a command options add the '-h' parameter after it.\n";
Terminal.init();

