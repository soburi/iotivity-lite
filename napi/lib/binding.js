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
    var _ipv4 = new addon.OCIPv4Addr();
    console.dir(_ipv4);
    var _endpointdevaddr = new addon.OCEndpointDevAddr();
    console.dir(_endpointdevaddr );
    console.dir(_endpointdevaddr.ipv4 );
    console.dir(_endpointdevaddr.ipv4.port );
    console.log("-----------------------------");
}

module.exports = IotivityLite;
