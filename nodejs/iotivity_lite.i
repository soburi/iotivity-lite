%module iotivity_lite
%include "typemaps.i"
%include "arrays_javascript.i"

%{
#include "oc_config.h"
#include "util/pt/pt.h"
#include "util/oc_process.h"
#include "util/oc_etimer.h"
#include "util/oc_mem_trace.h"
#include "util/oc_mmem.h"
#include "util/oc_memb.h"
#include "util/oc_timer.h"
#include "util/oc_list.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/transactions.h"
#include "messaging/coap/separate.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/coap_signal.h"
#include "messaging/coap/conf.h"
#include "messaging/coap/engine.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
#include "port/oc_storage.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_base64.h"
#include "oc_blockwise.h"
#include "oc_buffer.h"
#include "oc_buffer_settings.h"
#include "oc_client_state.h"
#include "oc_clock_util.h"
#include "oc_cloud.h"
#include "oc_collection.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_discovery.h"
#include "oc_endpoint.h"
#include "oc_enums.h"
#include "oc_helpers.h"
#include "oc_introspection.h"
#include "oc_network_events.h"
#include "oc_network_monitor.h"
#include "oc_obt.h"
#include "oc_pki.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_session_events.h"
#include "oc_signal_event_loop.h"
#include "oc_swupdate.h"
#include "oc_uuid.h"
#include "OCCredType.h"
#include "OCAceConnectionType.h"
#include "OCAceSubjectType.h"
#include "OCAceWildcard.h"
#include "OCCloudError.h"
#include "OCCloudPrivisioningStatus.h"
#include "OCCredUsage.h"
#include "OCDiscoveryFlags.h"
#include "OCEncoding.h"
#include "OCEventCallbackResult.h"
#include "OCFVersion.h"
#include "OCMethod.h"
#include "OCPositionDescription.h"
#include "OCSessionState.h"
#include "OCStatus.h"
#include "OCSoftwareUpdateResult.h"
#include "OCType.h"
#include "OCQos.h"
#include "OCCloudContext.h"
#include "OCCloudStore.h"
#include "OCCredData.h"
#include "OCDeviceInfo.h"
#include "OCEndpoint.h"
#include "OCIPv4Addr.h"
#include "OCIPv6Addr.h"
#include "OCLEAddr.h"
#include "OCLinkParams.h"
#include "OCPlatformInfo.h"
#include "OCRep.h"
#include "OCRequest.h"
#include "OCRequestHandler.h"
#include "OCResponse.h"
#include "OCRole.h"
#include "OCResourceType.h"
#include "OCCred.h"
#include "OCCreds.h"
#include "OCAceResource.h"
#include "OCSecurityAce.h"
#include "OCSecurityAcl.h"
#include "OCRepresentation.h"
#include "OCLink.h"
#include "OCCollection.h"
#include "OCResource.h"
#include "OCUuid.h"
#include "OCArray.h"
#include "OCClientCallback.h"
#include "OCClientResponse.h"
#include "OCResponseBuffer.h"
#include "OCSeparateResponse.h"
#include "OCMain.h"
#include "OCHandler.h"
#include "TypeMapping.h"
%}


%ignore g_encoder;
%ignore root_map;
%ignore links_array;
%ignore g_err;
%ignore message_buffer_handler;
%ignore coap_engine;
%ignore oc_network_events;
%ignore oc_session_events;
%ignore coap_error_message;
%ignore coap_status_code;
%ignore oc_etimer_process;
%ignore oc_process_current;
%ignore oc_process_list;

%ignore coap_observe_handler;
%ignore coap_separate_accept;

%ignore oc_handler_t;
%ignore oc_properties_cb;
%ignore oc_swupdate_cb;

%ignore oc_collection_s;
%ignore oc_resource_s;

%ignore OCAceConnectionType::operator=;
%ignore OCAceSubjectType::operator=;
%ignore OCAceWildcard::operator=;
%ignore OCCloudError::operator=;
%ignore OCCloudPrivisioningStatus::operator=;
%ignore OCCredType::operator=;
%ignore OCCredUsage::operator=;
%ignore OCDiscoveryFlags::operator=;
%ignore OCEncoding::operator=;
%ignore OCEventCallbackResult::operator=;
%ignore OCFVersion::operator=;
%ignore OCMethod::operator=;
%ignore OCPositionDescription::operator=;
%ignore OCSessionState::operator=;
%ignore OCStatus::operator=;
%ignore OCSoftwareUpdateResult::operator=;
%ignore OCType::operator=;
%ignore OCQos::operator=;


%typemap(in) fp_void_int {
  $1 = v8func_passthrough($input);
}

/*
%ignore OCHandler(fp_void_int, fp_void_void, fp_void_void, fp_void_void);

%native(new_OCHandler) SwigV8ReturnValue new_ochandler(const SwigV8Arguments *args);
%{
static SwigV8ReturnValue new_ochandler(const SwigV8Arguments &args) {
  SWIGV8_RETURN(SWIGV8_UNDEFINED());
}
%}
*/
%include oc_config.h
/*
%include util/pt/lc-switch.h
%include util/pt/lc.h
%include util/pt/lc-addrlabels.h
%include util/pt/pt-sem.h
*/
%include util/pt/pt.h
%include util/oc_process.h
%include util/oc_etimer.h
%include util/oc_mem_trace.h
%include util/oc_mmem.h
%include util/oc_memb.h
%include util/oc_timer.h
%include util/oc_list.h
%include messaging/coap/oc_coap.h
%include messaging/coap/transactions.h
%include messaging/coap/separate.h
%include messaging/coap/coap.h
%include messaging/coap/observe.h
%include messaging/coap/constants.h
%include messaging/coap/coap_signal.h
%include messaging/coap/conf.h
%include messaging/coap/engine.h
%include port/oc_assert.h
%include port/oc_clock.h
%include port/oc_connectivity.h
%include port/oc_log.h
%include port/oc_network_events_mutex.h
%include port/oc_random.h
%include port/oc_storage.h
%include oc_acl.h
%include oc_api.h
%include oc_base64.h
%include oc_blockwise.h
%include oc_buffer.h
%include oc_buffer_settings.h
%include oc_client_state.h
%include oc_clock_util.h
%include oc_cloud.h
%include oc_collection.h
%include oc_core_res.h
%include oc_cred.h
%include oc_discovery.h
%include oc_endpoint.h
%include oc_enums.h
%include oc_helpers.h
%include oc_introspection.h
%include oc_network_events.h
%include oc_network_monitor.h
%include oc_obt.h
%include oc_pki.h
%include oc_rep.h
%include oc_ri.h
%include oc_session_events.h
%include oc_signal_event_loop.h
%include oc_swupdate.h
%include oc_uuid.h
%include OCAceConnectionType.h
%include OCAceSubjectType.h
%include OCAceWildcard.h
%include OCCloudError.h
%include OCCloudPrivisioningStatus.h
%include OCCredType.h
%include OCCredUsage.h
%include OCDiscoveryFlags.h
%include OCEncoding.h
%include OCEventCallbackResult.h
%include OCFVersion.h
%include OCMethod.h
%include OCPositionDescription.h
%include OCSessionState.h
%include OCStatus.h
%include OCSoftwareUpdateResult.h
%include OCType.h
%include OCQos.h

%include OCCloudContext.h
%include OCCloudStore.h
%include OCCredData.h
%include OCDeviceInfo.h
%include OCEndpoint.h
%include OCIPv4Addr.h
%include OCIPv6Addr.h
%include OCLEAddr.h
%include OCLinkParams.h
%include OCPlatformInfo.h
%include OCRep.h
%include OCRequest.h
%include OCRequestHandler.h
%include OCResponse.h
%include OCRole.h
%include OCResourceType.h
%include OCCred.h
%include OCCreds.h
%include OCAceResource.h
%include OCSecurityAce.h
%include OCSecurityAcl.h
%include OCRepresentation.h
%include OCLink.h
%include OCCollection.h
%include OCResource.h
%include OCUuid.h
%include OCArray.h
%include OCClientCallback.h
%include OCClientResponse.h
%include OCResponseBuffer.h
%include OCSeparateResponse.h

%include OCMain.h
%include OCHandler.h
