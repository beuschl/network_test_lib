#ifndef NETWORK_TEST_LIB_NET_CLIENT_H
#define NETWORK_TEST_LIB_NET_CLIENT_H

#include <memory>
#include "asio/io_service.hpp"
#include "endpoint.h"

namespace {

class Tls_component;

class Net_client {
public:
    using Sptr = std::shared_ptr<Net_client>;
    using Uptr = std::unique_ptr<Net_client>;
    using Receive_handler = std::function<void(::net::Shared_payload&& receive_buffer)>;

    virtual ~Net_client() = default;

    virtual void connect(::net::Endpoint remote_endpoint,
                         std::function<void(const asio::error_code&)> lambda) = 0;

    virtual void transmit(::net::Shared_payload tx_buffer,
                          std::function<void(const ::asio::error_code&, std::size_t)> lambda) = 0;
    virtual void receive(Receive_handler receive_handler,
                         ::net::Shared_payload&& received_payload) = 0;
    virtual void sync_receive(Receive_handler receive_handler,
                              ::net::Shared_payload&& received_payload) = 0;

    virtual ::net::Endpoint const& local_endpoint() const = 0;
    virtual ::net::Endpoint const& remote_endpoint() const = 0;
};
}

#endif
