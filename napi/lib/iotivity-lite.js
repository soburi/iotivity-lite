try {
    module.exports = require('../../build/Debug/iotivity-lite-native');
} catch (ex) {
    module.exports = require('../../build/Release/iotivity-lite-native');
}
