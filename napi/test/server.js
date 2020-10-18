const IotivityLite = require("../lib/iotivity-lite.js");
const assert = require("assert");

//var quit = 0;
//static pthread_mutex_t mutex;
//static pthread_cond_t cv;
//static struct timespec ts;
var light_state = false;
/*
function set_device_custom_property(data)
{
  IotivityLite.oc_set_custom_device_property(purpose, "desk lamp");
}
*/

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
  var stack = new Error().stack
  console.log( stack )

  console.log("app_init");
  var ret;
  console.log("call oc_init_platform");
  ret = IotivityLite.oc_init_platform("Intel", init_platform_cb, "init_platform_cb_param");
  console.log("end call oc_init_platform");
  console.log("call oc_add_device");
  ret = IotivityLite.oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "ocf.1.0.0",
                       "ocf.res.1.0.0", add_device_cb, "add_device_cb_param");
  console.log("end oc_add_device");
  var stack = new Error().stack
  console.log( stack )
  return ret;
}

function get_light(request, iface_mask, user_data)
{
  console.log("GET_light:\n");
  console.log(request);
  console.log(iface_mask);
  console.log(user_data);
  var root = IotivityLite.oc_rep_start_root_object();
  switch (iface_mask) {
  case OCInterfaceMask.OC_IF_BASELINE:
    IotivityLite.oc_process_baseline_interface(request.resource);
  case OCInterfaceMask.OC_IF_RW:
    IotivityLite.oc_rep_set_boolean(root, state, light_state);
    break;
  default:
    break;
  }
  IotivityLite.oc_rep_end_root_object();
  IotivityLite.oc_send_response(request, OCStatus.OC_STATUS_OK);
  console.log("Light state " + light_state);
}

function post_light(request, iface_mask, user_data)
{
  console.log("POST_light:\n");
  console.log(request);
  console.log(iface_mask);
  console.log(user_data);
/*
  (void)user_data;
  (void)iface_mask;
  PRINT("POST_light:\n");
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      PRINT("value: %d\n", state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
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

  var res = IotivityLite.oc_new_resource("lightbulb", "/light/1", 1, 0);//new IotivityLite.OCResource();
  console.dir(res);
  IotivityLite.oc_resource_bind_resource_type(res, "oic.r.light");
  IotivityLite.oc_resource_bind_resource_interface(res, IotivityLite.OCInterfaceMask.OC_IF_RW);
  IotivityLite.oc_resource_set_default_interface(res, IotivityLite.OCInterfaceMask.OC_IF_RW);
  IotivityLite.oc_resource_set_discoverable(res, true);
  IotivityLite.oc_resource_set_periodic_observable(res, 1);
  IotivityLite.oc_resource_set_request_handler(res, IotivityLite.OCMethod.OC_GET, get_light, null);
  IotivityLite.oc_resource_set_request_handler(res, IotivityLite.OCMethod.OC_POST, post_light, null);
  IotivityLite.oc_resource_set_request_handler(res, IotivityLite.OCMethod.OC_PUT, put_light, null);
  IotivityLite.oc_add_resource(res);
}
function signal_event_loop()
{
  console.log(new Date);
  var stack = new Error().stack
  console.log( stack )
  console.log("---- signal_event_loop ---");
  //pthread_mutex_lock(&mutex);
  //pthread_cond_signal(&cv);
  //pthread_mutex_unlock(&mutex);
}

function handle_signal()
{
  console.log("IotivityLite.oc_main_shutdown(handler)");
  IotivityLite.oc_main_shutdown();
  console.log("end IotivityLite.oc_main_shutdown(handler)");
  //signal_event_loop();
  //quit = 1;
}

/*
  oc_clock_time_t next_event;
*/
  process.on('SIGINT', handle_signal);

  IotivityLite.oc_storage_config("./server_creds");

  var handler = new IotivityLite.OCHandler();
  handler.init = app_init;
  handler.signal_event_loop = signal_event_loop;
  handler.register_resources = register_resources;
  handler.request_entry = function() { console.log("-- request_entry --"); };

  console.log("IotivityLite.oc_main_init(handler)");
  var init = IotivityLite.oc_main_init(handler);
  console.log("end IotivityLite.oc_main_init(handler)");
/*
  while (quit != 1) {
    next_event = IotivityLite.oc_main_poll();
    //pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      //pthread_cond_wait(&cv, &mutex);
    } else {
      //ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      //ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      //pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    //pthread_mutex_unlock(&mutex);
  }
*/

