#include <oc_endpoint.h>
class OCEndpoint : public oc_endpoint_t {};

#include <napi.h>

class OCEndpoint : public Napi::ObjectWrap<OCEndpoint>
{
public:
    OCEndpoint(const Napi::CallbackInfo&);
    Napi::Value Greet(const Napi::CallbackInfo&);

    static Napi::Function GetClass(Napi::Env);

private:
    std::string _greeterName;
};

