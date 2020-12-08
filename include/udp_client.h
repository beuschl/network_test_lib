#ifndef NETWORK_TEST_LIB_NET_CLIENT_UDP_H
#define NETWORK_TEST_LIB_NET_CLIENT_UDP_H

#include <memory>
#include "asio/io_service.hpp"
#include "asio/ip/udp.hpp"
#include "net_client.h"
#include "endpoint.h"

namespace {

class Udp_client : public Net_client {
public:
    Udp_client(std::shared_ptr<::asio::io_service> io_service, ::net::Endpoint local_endpoint)
        : m_io_service{std::move(io_service)}
        , m_socket{*m_io_service}
        , m_local_endpoint{local_endpoint}
        , m_remote_endpoint{}
    {
        asio::error_code ec;
        (void)m_socket.open(local_endpoint.get_udp_base().protocol(), ec);
        m_socket.set_option(asio::socket_base::reuse_address(true), ec);
        (void)m_socket.bind(local_endpoint.get_udp_base(), ec);
        m_local_endpoint.port(m_socket.local_endpoint().port());
    }

    void connect(::net::Endpoint remote_endpoint,
                 std::function<void(const ::asio::error_code&)> /* lambda */) override
    {
        m_remote_endpoint = std::move(remote_endpoint);
    }

    void transmit(::net::Shared_payload tx_buffer,
                  std::function<void(const ::asio::error_code&, std::size_t)> lambda) override
    {
        m_socket.async_send_to(asio::buffer(*tx_buffer, tx_buffer->size()),
                                   m_remote_endpoint.get_udp_base(), lambda);
    }

    ::net::Endpoint const& local_endpoint() const override
    {
        return m_local_endpoint;
    }
    :net::Endpoint const& remote_endpoint() const override
    {
        return m_remote_endpoint;
    }

    void receive(Receive_handler receive_handler,
                 ::net::Shared_payload&& received_payload) override
    {
        m_socket.async_receive(::asio::null_buffers(), [this, receive_handler,
                                                        received_buffer =
                                                            std::move(received_payload)](
                                                           auto error, auto) mutable {
            if (!error) {
                received_buffer->resize(m_socket.available());
                m_socket.receive(asio::buffer(*received_buffer, received_buffer->size()), 0, error);
                if (!error) {
                    receive_handler(std::move(received_buffer));
                }
            }
        });
    }

    void sync_receive(Receive_handler receive_handler,
                      ::net::Shared_payload&& received_payload) override
    {
        received_payload->resize(m_socket.available());
        m_socket.receive(::asio::buffer(*received_payload, received_payload->size()));
        receive_handler(std::move(received_payload));
    }

    ::asio::ip::udp::socket& get_asio_socket() { return m_socket; }

private:
    std::shared_ptr<::asio::io_service> m_io_service;
    ::asio::ip::udp::socket m_socket;
    ::net::Endpoint m_local_endpoint;
    ::net::Endpoint m_remote_endpoint;
};
}

#endif
