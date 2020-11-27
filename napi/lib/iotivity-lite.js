try {
  module.exports = require('../../build/Debug/iotivity-lite-native');
}
catch(error) {
  module.exports = require('../../build/Release/iotivity-lite-native');
}
