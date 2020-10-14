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

function test_oc_set_con_res_announced()
{
    IotivityLite.oc_set_con_res_announced(true);
}

function test_oc_storage_config()
{
    return IotivityLite.oc_storage_config("./client_creds");
}

function test_oc_main_init() 
{
	var handler = new IotivityLite.OCHandler();
	handler.init = function() { console.log("-- init --"); };
	handler.signal_event_loop = function() { console.log("-- signal_event_loop --"); };
	handler.register_resources = function() { console.log("-- register_resources --"); };
	handler.request_entry = function() { console.log("-- request_entry --"); };


	return IotivityLite.oc_main_init(handler);
}

assert.doesNotThrow(testBasic)
assert.doesNotThrow(testConstructOCIPv4Addr)
assert.doesNotThrow(test_oc_set_con_res_announced)
assert.doesNotThrow(test_oc_storage_config, 0)
assert.equal(test_oc_storage_config(), 0)
assert.doesNotThrow(test_oc_main_init, 0)
assert.equal(test_oc_main_init(), 0)

//assert.throws(testInvalidParams, undefined, "testInvalidParams didn't throw");
//
//testBasic();

console.log("Tests passed- everything looks OK!");
