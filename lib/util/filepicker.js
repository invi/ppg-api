// # filepicker
// Utilities to select file to load/save

const {Cc, Ci} = require("chrome");

// ### pickNSSPath()
// 
// Method to pick the NSS library path 
// TODO: Merge with filepicker
exports.pickNSSPath = function(libName) { 
  const winUtils = require("window-utils"); const nsIFilePicker = Ci.nsIFilePicker;
  var fp = Cc["@mozilla.org/filepicker;1"]
                 .createInstance(nsIFilePicker);

  fp.init(winUtils.activeWindow, "Select NSS(" + libName + ") library", nsIFilePicker.modeOpen);
  fp.appendFilter("NSS library (" + libName + ")", libName);
  fp.appendFilters(nsIFilePicker.filterAll);

  var rv = fp.show();
  if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
    var file = fp.file;
    // Get the path as string. Note that you usually won't 
    // need to work with the string paths.
    var path = fp.file.path;
    // work with returned nsILocalFile...
    return file;
  }
  return 0;
}

exports.filePicker = function() { 
  const winUtils = require("window-utils"); const nsIFilePicker = Ci.nsIFilePicker;
  var fp = Cc["@mozilla.org/filepicker;1"]
                 .createInstance(nsIFilePicker);

  fp.init(winUtils.activeWindow, "Import key", nsIFilePicker.modeOpen);
  fp.appendFilter("Armored Public Key", "*.asc");
  fp.appendFilters(nsIFilePicker.filterAll);

  var rv = fp.show();
  if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
    var file = fp.file;
    // Get the path as string. Note that you usually won't 
    // need to work with the string paths.
    var path = fp.file.path;
    // work with returned nsILocalFile...
    return file;
  }
  return 0;
}

exports.saveFilePicker = function() { 
  const winUtils = require("window-utils"); const nsIFilePicker = Ci.nsIFilePicker;
  var fp = Cc["@mozilla.org/filepicker;1"]
                 .createInstance(nsIFilePicker);

  fp.init(winUtils.activeWindow, "Export to file", nsIFilePicker.modeSave);
  fp.appendFilter("Armored Public Key", "*.asc");
  fp.appendFilters(nsIFilePicker.filterAll);

  var rv = fp.show();
  if (rv == nsIFilePicker.returnOK || rv == nsIFilePicker.returnReplace) {
    var file = fp.file;
    // Get the path as string. Note that you usually won't 
    // need to work with the string paths.
    var path = fp.file.path;
    // work with returned nsILocalFile...
    return file;
  }
  return 0;
}
