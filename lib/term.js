const {data} = require('self');
const tabs = require("tabs");
const misc = require("util/misc");
const {worker_messages} = require("worker_messages");

var menuitem = require("menuitems").Menuitem({
  id: "clickme",
  menuid: "menu_ToolsPopup",
  label: "Pidgeon PG Terminal",
  onCommand: function() {
    term.open();
  },
});

var term = {
  open: function() {
    tabs.open({
      url: misc.data_url("term/ppgterm.html"),
      onReady: function(tab) {
        var worker = tab.attach({
          contentScriptFile: [
                              misc.data_url("term/optparse.js"),
                              misc.data_url("term/terminal.js"),
                              misc.data_url("term/commands.js"),
                              misc.data_url("term/ppgterm.js")],
        });
        worker_messages.subscribe(worker);
      }
    });
  }
}

exports.term = term;
