const IL = require("../lib/iotivity-lite.js");
const assert = require("assert");
/*
#define MAX_URI_LENGTH (30)
static char light_1[MAX_URI_LENGTH];
var light_server;
static bool light_state = false;
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
  console.log("app_init");

  console.log("call oc_init_platform");
  var ret = IL.oc_init_platform("Intel Corporation", null, null);
  console.log("end call oc_init_platform");

  console.log("call oc_add_device");
  ret |= IL.oc_add_device("/oic/d", "oic.d.phone", "Generic Client", "ocf.1.0.0",
                       "ocf.res.1.0.0", null, null);

  return ret;
}

function stop_observe(data)
{
  PRINT("Stopping OBSERVE\n");
  IL.oc_stop_observe(light_1, light_server);
  return OC_EVENT_DONE;
}
/*
static void
post_light(oc_client_response_t *data)
{
  PRINT("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);
}

static void
observe_light(oc_client_response_t *data)
{
  PRINT("OBSERVE_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      PRINT("%d\n", rep->value.boolean);
      light_state = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_post(light_1, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !light_state);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST\n");
  } else
    PRINT("Could not init POST\n");
}
*/

function discovery(di, uri, types, iface_mask, endpoint, bm, user_data)
{
  console.log("-- discovery --");
//  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

//  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
//    char *t = IL.oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.light", 11) == 0) {
      strncpy(light_1, uri, uri_len);
      light_1[uri_len] = '\0';

      light_server = IL.oc_endpoint_list_copy(endpoint);

      console.log("Resource %s hosted at endpoints:\n", light_1);
      ep = endpoint;
      while (ep != null) {
        //PRINTipaddr(*ep);
        PRINT("\n");
        //ep = ep->next;
      }

      IL.oc_do_observe(light_1, light_server, null, observe_light, LOW_QOS, null);
      IL.oc_set_delayed_callback(null, stop_observe, 10);
      return OC_STOP_DISCOVERY;
    }
//  }
  return OC_CONTINUE_DISCOVERY;
}

function issue_requests()
{
  console.log("-- issue_requests --");
  IL.oc_do_ip_discovery("core.light", discovery, "discovery_data");
}

function handle_signal()
{
  console.log("IL.oc_main_shutdown()");
  IL.OCMain.main_shutdown();
  console.log("end IL.oc_main_shutdown()");
}

async function main() {
  process.on('SIGINT', handle_signal);

  IL.oc_storage_config("./server_creds");

  oc_set_con_res_announced(false);
  handler.init = app_init;

  handler.request_entry = issue_requests;

  console.log("IL.oc_main_init(handler)");
  var init = IL.OCMain.main_init(handler);
  console.log("end IL.oc_main_init(handler)");
  await IL.OCMain.main_loop();
  console.log("end IL.oc_main_loop()");
};

main();
