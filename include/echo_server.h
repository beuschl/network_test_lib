#ifndef NETWORK_TEST_LIB_ECHO_SERVER_H
#define NETWORK_TEST_LIB_ECHO_SERVER_H

#include <memory>
#include "endpoint.h"

namespace {

class Echo_server {
public:
    using Uptr = std::unique_ptr<Echo_server>;

    virtual ~Echo_server() = default;

    virtual void listen() = 0;
    virtual ::net::Endpoint const& local_endpoint() const = 0;
    virtual std::uint32_t connection_received_data(std::uint16_t connection_index) const = 0;
};
}

#endif
