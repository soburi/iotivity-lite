var path = '../build/Release/';
if (process.env.IOTIVITY_LITE_DEBUG == '1') { path = '../build/Debug/'; }
const addon = require(path + 'iotivity-lite-native');
module.exports = addon;
