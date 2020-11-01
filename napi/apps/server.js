const IL = require("../lib/iotivity-lite.js");
const assert = require("assert");

var light_state = false;

function init_platform_cb(parm) {
  console.log("init_platform_cb");
  console.log(param);

  var stack = new Error().stack
  console.log( stack )
}

function add_device_cb(param) {
  console.log("add_device_cb");
  console.log(param);
  var stack = new Error().stack
  console.log( stack )

}

function app_init()
{
  console.log("app_init");

  console.log("call oc_init_platform");
  var ret = IL.oc_init_platform("Intel", init_platform_cb, "init_platform_cb_param");
  console.log("end call oc_init_platform");

  console.log("call oc_add_device");
  ret = IL.oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "ocf.1.0.0",
                       "ocf.res.1.0.0", add_device_cb, "add_device_cb_param");
  console.log("end oc_add_device");
  return ret;
}

function get_light(request, iface_mask, user_data)
{
  console.log("GET_light:\n");
  console.log(request);
  console.log(iface_mask);
  console.log(user_data);
  var root = IL.oc_rep_start_root_object();
  switch (iface_mask) {
  case OCInterfaceMask.OC_IF_BASELINE:
    IL.oc_process_baseline_interface(request.resource);
  case OCInterfaceMask.OC_IF_RW:
    IL.oc_rep_set_boolean(root, state, light_state);
    break;
  default:
    break;
  }
  IL.oc_rep_end_root_object();
  IL.oc_send_response(request, OCStatus.OC_STATUS_OK);
  console.log("Light state " + light_state);
}

function post_light(request, iface_mask, user_data)
{
  console.log("POST_light:\n");
  console.log(request);
  console.log(iface_mask);
  console.log(user_data);
  //(void)user_data;
  //(void)iface_mask;
  console.log("POST_light:\n");

  var state = false;
  var rep = request.request_payload;
/*
  while (rep != null) {
    console.log("key: %s ", oc_string(rep.name));
    switch (rep.type) {
    case OC_REP_BOOL:
      state = rep.value.boolean;
      PRINT("value: %d\n", state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep.next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  light_state = state;
*/
}

function put_light(request, iface_mask, user_data)
{
  post_light(request, iface_mask, user_data);
}

function register_resources()
{
//  oc_resource_t *res = oc_new_resource("lightbulb", "/light/1", 1, 0);
  console.log("---- register_resources ----");

  var res = IL.oc_new_resource("lightbulb", "/light/1", 1, 0);//new IL.OCResource();
  console.dir(res);
  IL.oc_resource_bind_resource_type(res, "oic.r.light");
  IL.oc_resource_bind_resource_interface(res, IL.OCInterfaceMask.OC_IF_RW);
  IL.oc_resource_set_default_interface(res, IL.OCInterfaceMask.OC_IF_RW);
  IL.oc_resource_set_discoverable(res, true);
  IL.oc_resource_set_periodic_observable(res, 1);
  IL.oc_resource_set_request_handler(res, IL.OCMethod.OC_GET, get_light, null);
  IL.oc_resource_set_request_handler(res, IL.OCMethod.OC_POST, post_light, null);
  IL.oc_resource_set_request_handler(res, IL.OCMethod.OC_PUT, put_light, null);
  IL.oc_add_resource(res);
}

function handle_signal()
{
  console.log("IL.oc_main_shutdown()");
  IL.OCMain.main_shutdown();
  console.log("end IL.oc_main_shutdown()");
}

/*
  oc_clock_time_t next_event;
*/

async function main() {
  process.on('SIGINT', handle_signal);

  IL.oc_storage_config("./server_creds");

  var handler = new IL.OCHandler();
  handler.init = app_init;
  handler.register_resources = register_resources;
  handler.request_entry = function() { console.log("-- request_entry --"); };

  console.log("IL.oc_main_init(handler)");
  var init = IL.OCMain.main_init(handler);
  console.log("end IL.oc_main_init(handler)");
  await IL.OCMain.main_loop();
  console.log("end IL.oc_main_loop()");
};

main();
