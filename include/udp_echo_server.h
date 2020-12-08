#ifndef NETWORK_TEST_LIB_UDP_ECHO_SERVER_HPP
#define NETWORK_TEST_LIB_UDP_ECHO_SERVER_HPP

#include <array>
#include <memory>
#include <thread>
#include "asio/io_service.hpp"
#include "asio/ip/udp.hpp"
#include "echo_server.h"
#include "endpoint.h"

namespace {

// Replies the received data (max 1024 chars)
class Echo_connection_udp : public std::enable_shared_from_this<Echo_connection_udp> {
public:
    explicit Echo_connection_udp(std::shared_ptr<::asio::ip::udp::socket> socket)
        : m_socket{std::move(socket)}
        , m_sender_endpoint{}
        , m_data{}
        , m_data_received{0}
    {
    }

    void receive()
    {
        auto asio_buffer = asio::buffer(m_data);
        m_socket->async_receive_from(
            asio_buffer, m_sender_endpoint,
            [self = shared_from_this(),
             keep_buffer = std::move(asio_buffer)](auto error, auto bytes_transferred) {
                if (!error && bytes_transferred > 0) {
                    self->m_data_received++;                    
                    self->m_socket->async_send_to(asio::buffer(self->m_data, bytes_transferred),
                                                      self->m_sender_endpoint, [self](auto, auto) {
                                                          // receive again
                                                          self->receive();
                                                      });
                }
                else {
                    // receive again
                    self->receive();
                }
            });
    }

    std::uint32_t data_received() const { return m_data_received; }


private:
    std::shared_ptr<::asio::ip::udp::socket> m_socket;
    asio::ip::udp::endpoint m_sender_endpoint;
    std::array<std::uint8_t, 1024> m_data;
    std::uint32_t m_data_received;
};

// Runs in own io_service thread
class Echo_server_udp : public Echo_server {
public:
    explicit Echo_server_udp(::net::Endpoint local_endpoint)
        : m_io_service{std::make_shared<asio::io_service>()}
        , m_local_endpoint{std::move(local_endpoint)}
        , m_iothread{std::thread([&m_io_service = m_io_service] {
            asio::io_service::work work(*m_io_service);
            m_io_service->run();
        })}
        , m_connections{}
    {
    }

    ~Echo_server_udp()
    {
        m_io_service->stop();
        m_iothread.join();
    }

    void listen() override
    {
        std::vector<std::uint8_t> addr_out;
        std::shared_ptr<asio::ip::udp::socket> socket;
        if (m_local_endpoint.is_v4()) {
            m_local_endpoint.address(:net::Internet_protocol::ipv4, std::back_inserter(addr_out));

            using address_type = asio::ip::address_v4::bytes_type;
            address_type address_raw;
            std::copy_n(addr_out.begin(), address_raw.size(), address_raw.begin());
            asio::ip::udp::endpoint asio_endpoint(
                asio::ip::address(asio::ip::address_v4(address_raw)), m_local_endpoint.port());
            socket = std::make_shared<asio::ip::udp::socket>(*m_io_service, asio_endpoint);
        }
        else {
            m_local_endpoint.address(::net::Internet_protocol::ipv6, std::back_inserter(addr_out));

            using address_type = asio::ip::address_v6::bytes_type;
            address_type address_raw;
            std::copy_n(addr_out.begin(), address_raw.size(), address_raw.begin());
            asio::ip::udp::endpoint asio_endpoint(
                asio::ip::address(asio::ip::address_v6(address_raw)), m_local_endpoint.port());
            socket = std::make_shared<asio::ip::udp::socket>(*m_io_service, asio_endpoint);
        }


        // on binding, ephemeral ports might be updated
        m_local_endpoint.port(socket->local_endpoint().port());

        m_connections.push_back(
            std::make_shared<Echo_connection_udp>(std::move(socket)));
        m_connections.back()->receive();
    }

    ::net::Endpoint const& local_endpoint() const override
    {
        return m_local_endpoint;
    }

    std::uint32_t connection_received_data(uint16_t connection_index) const override
    {
        return m_connections[connection_index]->data_received();
    }

private:
    std::shared_ptr<asio::io_service> m_io_service;
    ::net::Endpoint m_local_endpoint;
    std::thread m_iothread;
    std::vector<std::shared_ptr<Echo_connection_udp>> m_connections; // maintain connections
};
}

#endif
