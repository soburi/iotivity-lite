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

	var f = function(num) {
		console.log("---" + num);
	}

	//_addonInstance.callback(f)

    console.dir(_addonInstance);
    var _ipv4 = new addon.OCIPv4Addr();
    console.dir(_ipv4);
    console.dir(_ipv4.port);
    var _endpointdevaddr = new addon.DevAddr();
    console.dir(_endpointdevaddr );
    console.dir(_endpointdevaddr.ipv4 );
    console.dir(_endpointdevaddr.ipv4.port );

    _addonInstance.callback(_ipv4);

    console.log("-----------------------------");
}

module.exports = IotivityLite;
