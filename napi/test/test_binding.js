const IotivityLite = require("../lib/iotivity-lite.js");
const assert = require("assert");

assert(IotivityLite, "The expected module is undefined");

function testBasic()
{
    const instance = new IotivityLite.IotivityLite("hoge");
    //assert(instance.greet, "The expected method is not defined");
    //assert.strictEqual(instance.greet("kermit"), "mr-yeoman", "Unexpected value returned");
    console.dir(instance);
    console.dir(instance.device);
    val = instance.device;
    console.log(val);

    console.dir(instance.di);
}

function testInvalidParams()
{
    //const instance = new IotivityLite();
}

function testConstructOCIPv4Addr()
{
    var _ipv4 = new IotivityLite.OCIPv4Addr();
    console.dir(_ipv4);
    console.dir(_ipv4.port);
}

assert.doesNotThrow(testBasic, undefined, "testBasic threw an expection");
assert.doesNotThrow(testConstructOCIPv4Addr, undefined, "testConstructOCIPv4Addr threw an expection");
//assert.throws(testInvalidParams, undefined, "testInvalidParams didn't throw");
//
//testBasic();

console.log("Tests passed- everything looks OK!");
