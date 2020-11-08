#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <oc_api.h>
#include <oc_base64.h>
#include <oc_blockwise.h>
#include <oc_buffer.h>
#include <oc_buffer_settings.h>
#include <oc_client_state.h>
#include <oc_clock_util.h>
#include <oc_cloud.h>
#include <oc_collection.h>
#include <oc_core_res.h>
#include <oc_cred.h>
#include <oc_discovery.h>
#include <oc_endpoint.h>
#include <oc_enums.h>
#include <oc_helpers.h>
#include <oc_introspection.h>
#include <oc_network_events.h>
#include <oc_network_monitor.h>
#include <oc_obt.h>
#include <oc_pki.h>
#include <oc_rep.h>
#include <oc_ri.h>
#include <oc_session_events.h>
#include <oc_signal_event_loop.h>
#include <oc_swupdate.h>
#include <oc_uuid.h>
#include <oc_connectivity.h>
#include <oc_assert.h>
#include <oc_mem_trace.h>

struct oc_separate_response_iterator_t {
    oc_separate_response_t* current;
};
struct oc_collection_iterator_t {
    oc_collection_s* current;
};
struct oc_link_iterator_t {
    oc_link_s* current;
};
struct oc_sec_ace_iterator_t {
    oc_sec_ace_t* current;
};
struct oc_ace_res_iterator_t {
    oc_ace_res_t* current;
};
struct oc_cloud_context_iterator_t {
    oc_cloud_context_t* current;
};
struct oc_link_params_iterator_t {
    oc_link_params_t* current;
};
struct oc_rt_iterator_t {
    oc_rt_t* current;
};
struct oc_etimer_iterator_t {
    oc_etimer* current;
};
struct oc_event_callback_iterator_t {
    oc_event_callback_t* current;
};
struct oc_message_iterator_t {
    oc_message_t* current;
};
struct oc_role_iterator_t {
    oc_role_t* current;
};
struct oc_blockwise_state_iterator_t {
    oc_blockwise_state_s* current;
};
struct oc_session_event_cb_iterator_t {
    oc_session_event_cb* current;
};
struct oc_rep_iterator_t {
    oc_rep_s* current;
};
struct oc_endpoint_iterator_t {
    oc_endpoint_t* current;
};

struct oc_string_array_iterator_t {
    oc_string_array_t array;
    uint32_t index;
};


#ifdef __cplusplus
}
#endif
