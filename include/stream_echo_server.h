#ifndef NETWORK_TEST_LIB_STREAM_ECHO_SERVER_H
#define NETWORK_TEST_LIB_STREAM_ECHO_SERVER_H

#include <memory>
#include <mutex>
#include <thread>
#include "asio/io_service.hpp"
#include "asio/ip/tcp.hpp"
#include "asio/write.hpp"
#include "echo_server.h"

namespace {

namespace tcp {
class Protocol_description {
public:
    using Endpoint = ::net::Endpoint_tcp;
    using Acceptor = ::asio::ip::tcp::acceptor;
    using Socket = ::asio::ip::tcp::socket;

    static void update_port(Endpoint const& source, ::net::Endpoint& destination)
    {
        destination.port(source.port());
    }

    static void close_acceptor(Acceptor& acceptor)
    {
        if (acceptor.is_open()) {
            ::asio::error_code error;
            acceptor.close(error);
        }
    }
};
} // namespace tcp

// Replies the received data (max 1024 chars)
template<typename ProtocolDescriptionType>
class Echo_connection_stream
    : public std::enable_shared_from_this<Echo_connection_stream<ProtocolDescriptionType>> {
public:
    Echo_connection_stream(std::shared_ptr<typename ProtocolDescriptionType::Socket> socket)
        : m_socket{std::move(socket)}
        , m_data{}
        , m_data_received{0}
    {
    }

    void receive()
    {
        std::weak_ptr<Echo_connection_stream<ProtocolDescriptionType>> weak_self =
            this->shared_from_this();
        m_socket->async_read_some(::asio::buffer(m_data), [weak_self](auto error,
                                                                      auto bytes_transferred) {
            auto self = weak_self.lock();
            if (self && !error) {
                self->m_data_received++;

                ::asio::async_write(*self->m_socket,
                                    ::asio::buffer(self->m_data, bytes_transferred),
                                    [self](auto error, auto) {
                                        if (!error) {
                                            // receive again
                                            self->receive();
                                        }
                                    });
            }
        });
    }

    std::uint32_t data_received() const { return m_data_received; }

private:
    std::shared_ptr<typename ProtocolDescriptionType::Socket> m_socket;
    std::array<std::uint8_t, 1024> m_data;
    std::uint32_t m_data_received;
};

// Runs in own io_service thread
template<typename ProtocolDescriptionType>
class Echo_server_stream : public Echo_server {
public:
    using Protocol_socket = typename ProtocolDescriptionType::Socket;

    explicit Echo_server_stream(::net::Endpoint local_endpoint)
        : m_io_service{std::make_shared<asio::io_service>()}
        , m_local_endpoint{std::move(local_endpoint)}
        , m_acceptor{*m_io_service,
                     ::net::get_endpoint_base<typename ProtocolDescriptionType::Endpoint>(m_local_endpoint)}
        , m_acceptor_mutex{}
        , m_connections{}
    {
        // update local endpoint port
        ProtocolDescriptionType::update_port(m_acceptor.local_endpoint(), m_local_endpoint);
        m_iothread = std::thread([&m_io_service = m_io_service] {
            asio::io_service::work work(*m_io_service);
            m_io_service->run();
        });
    }

    ~Echo_server_stream()
    {
        {
            std::lock_guard<std::mutex> lk(m_acceptor_mutex);
            ProtocolDescriptionType::close_acceptor(m_acceptor);
        }
        m_io_service->stop();
        m_iothread.join();
        m_connections.clear();
    }

    void listen() override
    {
        std::lock_guard<std::mutex> lk(m_acceptor_mutex);
        if (m_acceptor.is_open()) {
            auto socket = std::make_shared<Protocol_socket>(*m_io_service);
            m_acceptor.async_accept(*socket, [this, socket](::asio::error_code const& error) {
                if (!error) {
                    m_connections.push_back(
                        std::make_shared<Echo_connection_stream<ProtocolDescriptionType>>(std::move(socket)));
                    m_connections.back()->receive();
                    listen();
                }
            });
        }
    }

    ::net::Endpoint const& local_endpoint() const override
    {
        return m_local_endpoint;
    }

    std::uint32_t connection_received_data(std::uint16_t connection_index) const override
    {
        return m_connections[connection_index]->data_received();
    }

private:
    std::shared_ptr<asio::io_service> m_io_service;
    :net::Endpoint m_local_endpoint;
    typename ProtocolDescriptionType::Acceptor m_acceptor;
    std::mutex m_acceptor_mutex;
    std::vector<std::shared_ptr<Echo_connection_stream<ProtocolDescriptionType>>>
        m_connections; // maintain connections
    mutable std::mutex m_identity_mutex;
    std::thread m_iothread;
};
}

#endif
