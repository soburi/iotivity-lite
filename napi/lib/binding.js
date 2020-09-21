const addon = require('../build/Release/iotivity-lite-native');

function IotivityLite(name) {
    this.greet = function(str) {
        return _addonInstance.greet(str);
    }
/*
    this.device = { get device() { return _addonInstance.device; }
	            set device(x) { _addonInstance.device(x); } }
*/
    var _addonInstance = new addon.IotivityLite(name);
    console.dir(_addonInstance);
    console.dir(_addonInstance.device);
    console.dir(_addonInstance.di);
}

module.exports = IotivityLite;
