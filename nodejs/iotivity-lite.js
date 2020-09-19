iotivity_lite=require(__dirname + '/build/Release/iotivity_lite.node'); console.dir(iotivity_lite);

modules = [
	'OCBufferSettings',
	'OCCoreRes',
	'OCClock',
	'OCCloud',
	'OCConnectivity',
	'OCEnum',
	'OCIntrospection',
	'OCMain',
	'OCObt',
	'OCPki',
	'OCRandom',
	'OCRep',
	'OCSessionEvents',
	'OCStorage',
	'OCSoftwareUpdate' ];

enums = [
	'OCAceConnectionType',
	'OCAceSubjectType',
	'OCAceWildcard',
	'OCCloudError',
	'OCCloudPrivisioningStatus',
	'OCCredType',
	'OCCredUsage',
	'OCDiscoveryFlags',
	'OCEncoding',
	'OCEventCallbackResult',
	'OCFVersion',
	'OCMethod',
	'OCPositionDescription',
	'OCQos',
	'OCSessionState',
	'OCStatus',
	'OCType',
	'OCSoftwareUpdateResult',
];

classes = [
	'CborEncoder',
	'OCAceResource',
	'OCAceSubject',
	'OCArray',
	'OCClientCallback',
	'OCClientResponse',
	'OCClockConstants',
	'OCCloudContext',
	'OCCloudStore',
	'OCCollection',
	'oc_content_format_t',
	'OCCredData',
	'OCCred',
	'OCCreds',
	'OCDeviceInfo',
	'OCEndpoint',
	'OCIPv4Addr',
	'OCIPv6Addr',
	'OCLEAddr',
	'OCLink',
	'OCLinkParams',
	'OCObtConstants',
	'OCPlatformInfo',
	'OCRepConstants',
	'OCRepresentation',
	'OCRequest',
	'OCResource',
	'OCResourceType',
	'OCResponseBuffer',
	'OCResponse',
	'OCRole',
	'OCSecurityAce',
	'OCSecurityAcl',
	'OCSeparateResponse',
	'OCUuid',
	'OCValue'
];

classes.forEach(e => {
	if( iotivity_lite.hasOwnProperty(e) ) {
		try {
			console.dir(eval('new iotivity_lite.' + e + '();') );
		}
		catch(e) {
			console.log("FAILED: " + e);
		}
	}
	else {
		console.log("NOT_FOUND: " + e);
	}
});

enums.forEach(e => {
	if( iotivity_lite.hasOwnProperty(e) ) {
		try {
			console.dir(eval('new iotivity_lite.' + e + '();') );
		}
		catch(e) {
			console.log("FAILED: " + e);
		}
	}
	else {
		console.log("NOT_FOUND: " + e);
	}
});


x = new iotivity_lite.OCCredType();
console.dir(x);
x = 1;

console.dir(x);
y = new iotivity_lite.OCSecurityAcl();

console.dir(y);
console.dir(y.rowneruuid);
console.dir(y.rowneruuid.id);
console.dir(y.rowneruuid.id);

console.dir(iotivity_lite.oc_clock_init);
iotivity_lite.oc_clock_init();
