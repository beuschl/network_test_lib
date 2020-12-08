#ifndef NETWORK_TEST_LIB_STREAM_CLIENT_H
#define NETWORK_TEST_LIB_STREAM_CLIENT_H

#include <memory>
#include "asio/io_service.hpp"
#include "asio/ip/udp.hpp"
#include "net_client.h"
#include "endpoint.h"

namespace {

namespace tcp {
class Protocol_description_client {
public:
    using Endpoint = ::net::Endpoint_tcp;
    using Socket = ::asio::ip::tcp::socket;

    static void update_port(Endpoint const& source, ::net::Endpoint& destination)
    {
        destination.port(source.port());
    }

    static void bind(Socket& socket, ::net::Endpoint const& local_endpoint)
    {
        ::asio::error_code error;
        socket.bind(::net::get_endpoint_base<Endpoint>(local_endpoint), error);
        if (error) {
            socket.close(error);
        }
    }
};
} // namespace tcp

template<typename ProtocolDescriptionType>
class Stream_client
    : public Net_client
    , public std::enable_shared_from_this<Stream_client<ProtocolDescriptionType>> {
public:
    using Protocol_socket = typename ProtocolDescriptionType::Socket;
    using Protocol_endpoint = typename ProtocolDescriptionType::Endpoint;

    Stream_client(std::shared_ptr<::asio::io_service> io_service,
                  ::net::Endpoint local_endpoint)
        : m_io_service{std::move(io_service)}
        , m_local_endpoint{std::move(local_endpoint)}
        , m_remote_endpoint{}
        , m_socket{*m_io_service}
    {
        asio::error_code ec;
        m_socket.open(
            ::net::get_endpoint_base<Protocol_endpoint>(m_local_endpoint).protocol(), ec);

        ProtocolDescriptionType::bind(m_socket, m_local_endpoint);
        ProtocolDescriptionType::update_port(m_socket.local_endpoint(), m_local_endpoint);
    }

    void connect(::net::Endpoint remote_endpoint,
                 std::function<void(const ::asio::error_code&)> lambda) override
    {
        m_remote_endpoint = std::move(remote_endpoint);
        std::weak_ptr<Stream_client<ProtocolDescriptionType>> weak_self = this->shared_from_this();
        m_socket.async_connect(
            ::net::get_endpoint_base<Protocol_endpoint>(m_remote_endpoint),
            [weak_self, lambda](auto error) {
                auto self = weak_self.lock();
                if (self) {
                    lambda(error);
                }
            });
    }

    void transmit(::net::Shared_payload tx_buffer,
                  std::function<void(const ::asio::error_code&, std::size_t)> lambda) override
    {
        m_socket.async_send(::asio::buffer(*tx_buffer, tx_buffer->size()), lambda);
    }

    ::net::Endpoint const& local_endpoint() const override
    {
        return m_local_endpoint;
    }

    ::net::Endpoint const& remote_endpoint() const override
    {
        return m_remote_endpoint;
    }

    void receive(Receive_handler receive_handler,
                 ::net::Shared_payload&& received_payload) override
    {
        m_socket.async_receive(asio::null_buffers(), [this, receive_handler,
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

    Protocol_socket& get_asio_socket() { return m_socket; }

private:
    std::shared_ptr<::asio::io_service> m_io_service;
    ::ac::com::service::net::Endpoint m_local_endpoint;
    ::ac::com::service::net::Endpoint m_remote_endpoint;
    Protocol_socket m_socket;
};
}

#endif
