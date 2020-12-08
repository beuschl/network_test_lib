#ifndef NETWORK_TEST_LIB_NET_ENDPOINT_H
#define NETWORK_TEST_LIB_NET_ENDPOINT_H

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <ostream>
#include <string>
#include <type_traits>
#include <utility>
#include <cassert>
#include <memory>
#include <vector>

#include "asio/ip/address.hpp"
#include "asio/ip/address_v4.hpp"
#include "asio/ip/address_v6.hpp"
#include "asio/ip/tcp.hpp"
#include "asio/ip/udp.hpp"
#include "asio/local/stream_protocol.hpp"

enum class Transport_protocol : std::uint8_t {
    tcp = 0,
    udp = 1,
    reserved = 255,
    none = reserved
};

struct Internet_protocol {
    struct Ipv4_tag {
        constexpr std::size_t length() const { return 4U; }
    };

    struct Ipv6_tag {
        constexpr std::size_t length() const { return 16U; }
    };
    static constexpr Ipv4_tag ipv4 = Ipv4_tag{};
    static constexpr Ipv6_tag ipv6 = Ipv6_tag{};
};

#if defined(UNIX)
#include <sys/un.h>
#include <cstddef>
#endif

namespace net {

using Shared_payload = std::shared_ptr<std::vector<std::uint8_t>>;
using Endpoint_udp = ::asio::ip::udp::endpoint;
using Endpoint_tcp = ::asio::ip::tcp::endpoint;

namespace internal {

::asio::ip::address_v4::bytes_type get_ipv4_bytes(::asio::ip::address const& address);
::asio::ip::address_v6::bytes_type get_ipv6_bytes(::asio::ip::address const& address);

}


/// This class represents a communication endpoint (UDP/TCP/UDS)
class Endpoint final {
public:
    using Scope_id = unsigned long;

    Endpoint();

    ///   Construct endpoint from underlying representation
    ///
    /// \param[in] base_endpoint Endpoint in underlying representation
    /// \param[in] scope Network scope identifier - typically represents the hardware interface for ipv6.
    explicit Endpoint(Endpoint_udp base_endpoint, Scope_id scope = default_scope_id);
    explicit Endpoint(Endpoint_tcp base_endpoint, Scope_id scope = default_scope_id);


    ///   Construct endpoint from string ip-Address (ip version auto detect)
    ///
    /// \param[in] protocol Type of transport protocol of this endpoint
    /// \param[in] address Ip-Address as string.
    /// \param[in] port Port number.
    /// \param[in] scope Network scope identifier - typically represents the hardware interface for ipv6.
    Endpoint(Transport_protocol protocol, std::string const& address,
             std::uint16_t port = ephemeral_port, Scope_id scope = default_scope_id);

    ///   Constructs an UDP/TCP endpoint from iterators 'begin' and 'end' and parameters 'port' and 'scope'
    /// \param[in] protocol Type of transport protocol of this endpoint.
    /// \param[in] begin Begin iterator to binary (IPV4/IPV6) address stored in network byte order.
    /// \param[in] end End iterator to binary (IPV4/IPV6) address stored in network byte order.
    /// \param[in] port TCP/UDP Port number (not needed for other protocols), 0 if not provided.
    /// \param[in] scope Network scope identifier (used only if address is of type IPV6), 0 if not provided.
    template<typename Iterator>
    Endpoint(Transport_protocol protocol, Iterator const& begin, Iterator const& end,
             std::uint16_t port = ephemeral_port, Scope_id scope = default_scope_id);

    ///   Constructs an UDP/TCP endpoint with IPV4/IPV6 address from iterator 'begin' and parameters 'port' and 'scope'
    /// \param[in] tag Specify IP protocol version, either Internet_protocol::ipv4 or Internet_protocol::ipv6
    /// \param[in] protocol Type of transport protocol of this endpoint.
    /// \param[in] begin Begin iterator to binary (IPV4/IPV6) address stored in network byte order.
    /// \param[in] port TCP/UDP Port number (not needed for other protocols), 0 if not provided.
    /// \param[in] scope Network scope identifier (used only if address is of type IPV6), 0 if not provided.
    template<typename Iterator>
    Endpoint(Internet_protocol::Ipv4_tag tag, Transport_protocol protocol, Iterator const& begin,
             std::uint16_t port = ephemeral_port, Scope_id scope = default_scope_id);
    template<typename Iterator>
    Endpoint(Internet_protocol::Ipv6_tag tag, Transport_protocol protocol, Iterator const& begin,
             std::uint16_t port = ephemeral_port, Scope_id scope = default_scope_id);

    ///   Constructs an endpoint with the copy constructor
    Endpoint(Endpoint const& other);
    
        ///   Assigns an endpoint.
    Endpoint& operator=(Endpoint const& other) &;

    ///   Constructs an endpoint with the move constructor
    Endpoint(Endpoint&& other) noexcept;

    ///   Assigns an endpoint.
    Endpoint& operator=(Endpoint&& other) & noexcept;

    ~Endpoint();

    ///    Returns the binary (IPV4/IPV6) address of the endpoint in network byte order
    /// \param[in] tag Specify IP protocol version, either Internet_protocol::ipv4 or Internet_protocol::ipv6.
    /// \param[out] out Output iterator to write the binary IPV4/IPV6 address to in network byte order.
    template<typename InternetProtocol, typename OutputIt>
    void address(InternetProtocol tag, OutputIt out) const;

    ///    Returns the binary (IPV4/IPV6) address of the endpoint in network byte order
    /// \return Binary ip address in network byte order
    std::vector<uint8_t> address() const;

    ///    Returns the string (IPV4/IPV6) address of the endpoint in network byte order
    /// \return String address of the endpoint.
    std::string address_to_string() const;


    ///   Returns the port number
    /// \return Port number of the endpoint.
    std::uint16_t port() const;


    ///   Sets the port number
    /// \param[in] port Port number to set.
    void port(std::uint16_t port);

    ///   Returns the scope-id
    /// \return Scope-id of the endpoint.
    Scope_id scope_id() const;

    ///   Sets the scope-id
    /// \param[in] scope_id Scope-id to set.
    void scope_id(Scope_id scope_id);

    ///   Returns whether this endpoint has an IPV6 address or not
    /// \retval true This endpoint has an IPV6 address.
    /// \retval false This endpoint has not an IPV6 address.
    bool is_v6() const;

    ///   Returns whether this endpoint has an IPV4 address or not
    /// \retval true This endpoint has an IPV4 address.
    /// \retval false This endpoint has not an IPV4 address.
    bool is_v4() const;

    ///   Returns whether this is an UDP endpoint or not
    /// \retval true This is an UDP endpoint.
    /// \retval false This is not an UDP endpoint.
    bool is_udp() const;

    ///   Returns whether this is a TCP endpoint or not
    /// \retval true This is a TCP endpoint.
    /// \retval false This is not a TCP endpoint.
    bool is_tcp() const;

    ///   Returns whether this endpoint has a multicast address or not
    /// \retval true This endpoint has a multicast address.
    /// \retval false This endpoint has not a multicast address.
    bool is_multicast() const;

    ///   Returns whether this endpoint is valid or not
    /// \retval true This is a valid endpoint.
    /// \retval false This is an invalid endpoint.
    bool is_valid() const;

    ///   Return the endpoint's transport protocol
    /// \return Transport protocol of the endpoint
    Transport_protocol transport_protocol() const;

    ///   Implements the same behavior as is_valid()
    /// \see is_valid()
    explicit operator bool() const;

    ///   Compares two endpoints if they are equal or not
    bool operator==(Endpoint const& other) const;

    ///   Less than compare operator.
    bool operator<(Endpoint const& other) const;

    /// Get endpoint in underlying technology format (asio udp)
    Endpoint_udp const& get_udp_base() const;
    /// Get endpoint in underlying technology format (asio tcp)
    Endpoint_tcp const& get_tcp_base() const;

    ///  Create an endpoint based on an universal address specifier
    /// \param[in] address The address specifier (see below)
    /// \return An Endpoint instance created from the provided information. This is an invalid endpoint if
    ///         \p address was ill-formed.
    ///
    /// Address specifiers are a universal way of specifying endpoint addresses of any supported type.
    /// The syntax is as follows:
    ///
    /// <proto>://<address>[%<scope>][#<port>]
    ///
    /// If \e proto is 'udp' or 'tcp':
    /// - \e address is an ipv4 or ipv6 address
    /// - \e scope (optional) is a numeric network scope identifier, typically represents the hardware interface for ipv6.
    /// - \e port (optional) is the numeric tcp/udp port of the endpoint. Defaults to 0 if not specified.
    ///
    /// If \e proto is 'uds'
    /// - \e address is a path to a file to use for a regular Unix domain socket
    /// - \e scope is not applicable and shall not be used
    /// - \e port is not applicable and shall not be used
    static Endpoint from_string(std::string const& address);

    ///  Get an universal address specifier based on the current endpoint
    /// \return The address specifier.
    std::string to_string() const;

    /// \eb_function{any}
    ///   Create an ephemeral endpoint for a specific protocol
    /// \param[in] endpoint Endpoint to create en ephemeral endpoint from
    /// \return An ephemeral Endpoint instance created from the provided information.
    ///
    /// \eb_exceptionsafety_nothrow
    ///
    /// \eb_expects{1}
    ///   endpoint.is_valid() == true
    ///
    /// \eb_defines{return}
    ///   For provided udp/tcp endpoints, the port number is 0 and the ip address is ANY.
    ///   All other properties are the same as in the endpoint passed.
    ///
    /// \eb_defines{uds}
    ///   For provided uds endpoints, filename is an empty string
    /// (is_abstract is ignored anyway - see UDS constructor).
    ///
    /// \eb_ensures{1}
    ///   is_valid() == true
    ///
    static Endpoint any(Endpoint const& endpoint);
#if defined(UNIX)
    // -2 for leading (in case of abstract_uds) and trailing null_terminator
    static constexpr std::size_t max_length = sizeof(sockaddr_un::sun_path) - 2;
#else
    // max_length set according to Linux implementation (i.e. 108 - 2 chars; see previous explanation for the -2).
    // This value has been arbitrarily chosen since there is no concrete non-UNIX use case.
    static constexpr std::size_t max_length = 106U;
#endif
    static constexpr Scope_id default_scope_id = 0U;
    static constexpr std::uint16_t ephemeral_port = 0U;

private:
    Transport_protocol m_protocol{Transport_protocol::none};
    union Endpoint_base {
        Endpoint_udp udp;
        Endpoint_tcp tcp;
        explicit Endpoint_base(Endpoint_udp&& ep) : udp{std::move(ep)} {}
        explicit Endpoint_base(Endpoint_tcp&& ep) : tcp{std::move(ep)} {}
        explicit Endpoint_base() {}
    };
    Endpoint_base m_endpoint{};
    Scope_id m_scope_id{default_scope_id};

    void init_ip_endpoint(::asio::ip::address const& ip_address, std::uint16_t port);
    template<typename IpAddressType>
    void init_ip_endpoint(IpAddressType ip_address, std::uint16_t port);
    template<typename Iterator>
    void init_ip_endpoint(Iterator const& begin, Iterator const& end, std::uint16_t port,
                          Scope_id scope, std::random_access_iterator_tag category);
    void copy_endpoint_base(Endpoint const& other);
    void move_endpoint_base(Endpoint&& other);
    void destruct_endpoint_base();

    template<typename F>
    auto call_on_base_address(F const& function) const
    {
        assert(is_udp() || is_tcp());

        if (m_protocol == Transport_protocol::udp) {
            return function(m_endpoint.udp.address());
        }
        else
        {
            return function(m_endpoint.tcp.address());
        }
    }

    ::asio::ip::address_v4::bytes_type get_address_bytes(Internet_protocol::Ipv4_tag tag) const;
    ::asio::ip::address_v6::bytes_type get_address_bytes(Internet_protocol::Ipv6_tag tag) const;
};

// Public API implementation
inline Endpoint::Endpoint() = default;

inline Endpoint::Endpoint(Endpoint_udp base_endpoint, Scope_id scope)
    : m_protocol{Transport_protocol::udp}
    , m_endpoint{((scope != default_scope_id) && base_endpoint.address().is_v6())
                     ? Endpoint_udp{::asio::ip::address{::asio::ip::address_v6{
                                        base_endpoint.address().to_v6().to_bytes(), scope}},
                                    base_endpoint.port()}
                     : std::move(base_endpoint)}
    , m_scope_id{scope}
{
}

inline Endpoint::Endpoint(Endpoint_tcp base_endpoint, Scope_id scope)
    : m_protocol{Transport_protocol::tcp}
    , m_endpoint{((scope != default_scope_id) && base_endpoint.address().is_v6())
                     ? Endpoint_tcp{::asio::ip::address{::asio::ip::address_v6{
                                        base_endpoint.address().to_v6().to_bytes(), scope}},
                                    base_endpoint.port()}
                     : std::move(base_endpoint)}
    , m_scope_id{scope}
{
}

inline Endpoint::Endpoint(Transport_protocol protocol, std::string const& address,
                          std::uint16_t port, Scope_id scope)
    : m_protocol{protocol}, m_endpoint{}, m_scope_id{scope}

{
    assert(is_valid());
    assert(is_udp() || is_tcp());

    ::asio::error_code ec;
    auto ip_address = ::asio::ip::address::from_string(address, ec);

    if (!ec) {
        if ((scope != default_scope_id) && ip_address.is_v6()) {
            auto ipv6_address = ip_address.to_v6();
            ipv6_address.scope_id(scope);
            ip_address = ipv6_address;
        }
        init_ip_endpoint(ip_address, port);
    }
    else {
        m_protocol = Transport_protocol::none;
    }
}

template<typename Iterator>
inline Endpoint::Endpoint(Transport_protocol protocol, Iterator const& begin, Iterator const& end,
                          std::uint16_t port, Scope_id scope)
    : m_protocol{protocol}, m_endpoint{}, m_scope_id{scope}

{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    using category = typename std::iterator_traits<Iterator>::iterator_category;
    init_ip_endpoint(begin, end, port, scope, category());
}

template<typename Iterator>
inline Endpoint::Endpoint(Internet_protocol::Ipv4_tag /* tag */, Transport_protocol protocol,
                          Iterator const& begin, std::uint16_t port, Scope_id scope)
    : Endpoint(protocol, begin,
               std::next(begin, std::tuple_size<::asio::ip::address_v4::bytes_type>::value), port,
               scope)
{
}

template<typename Iterator>
inline Endpoint::Endpoint(Internet_protocol::Ipv6_tag /* tag */, Transport_protocol protocol,
                          Iterator const& begin, std::uint16_t port, Scope_id scope)
    : Endpoint(protocol, begin,
               std::next(begin, std::tuple_size<::asio::ip::address_v6::bytes_type>::value), port,
               scope)
{
}

inline Endpoint::Endpoint(Endpoint const& other)
    : m_protocol{other.m_protocol}
    , m_scope_id{other.m_scope_id}
{
    copy_endpoint_base(other);
}

inline Endpoint& Endpoint::operator=(Endpoint const& other) &
{
    m_protocol = other.m_protocol;
    m_scope_id = other.m_scope_id;
    copy_endpoint_base(other);
    return *this;
}

inline Endpoint::Endpoint(Endpoint&& other) noexcept
    : m_protocol{other.m_protocol}
    , m_scope_id{other.m_scope_id}
{
    move_endpoint_base(std::move(other));
}

inline Endpoint& Endpoint::operator=(Endpoint&& other) & noexcept
{
    m_protocol = other.m_protocol;
    m_scope_id = other.m_scope_id;
    move_endpoint_base(std::move(other));
    return *this;
}

inline Endpoint::~Endpoint()
{
    destruct_endpoint_base();
}

template<typename InternetProtocol, typename OutputIt>
inline void Endpoint::address(InternetProtocol tag, OutputIt out) const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());

    auto const address_bytes = get_address_bytes(tag);
    std::copy(address_bytes.begin(), address_bytes.end(), out);
}

inline std::vector<uint8_t> Endpoint::address() const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());

    std::vector<uint8_t> ip{};
    if (is_v4()) {
        ip.reserve(Internet_protocol::ipv4.length());
        address(Internet_protocol::ipv4, std::back_inserter(ip));
    }
    else {
        ip.reserve(Internet_protocol::ipv6.length());
        address(Internet_protocol::ipv6, std::back_inserter(ip));
    }
    return ip;
}

inline std::string Endpoint::address_to_string() const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());

    return ((m_protocol == Transport_protocol::udp)
                ? m_endpoint.udp.address().to_string()
                : m_endpoint.tcp.address().to_string());
}

inline std::uint16_t Endpoint::port() const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    return ((m_protocol == Transport_protocol::udp)
                ? m_endpoint.udp.port()
                : m_endpoint.tcp.port());
}

inline void Endpoint::port(std::uint16_t port)
{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    ((m_protocol == Transport_protocol::udp)
         ? m_endpoint.udp.port(port)
         : m_endpoint.tcp.port(port));
}

inline Scope_id Endpoint::scope_id() const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    return m_scope_id;
}

inline void Endpoint::scope_id(Scope_id scope_id)
{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    if (this->scope_id() != scope_id) {
        m_scope_id = scope_id;
        if (is_v6()) {
            init_ip_endpoint(call_on_base_address([scope_id](auto const& address) {
                                 return ::asio::ip::address{
                                     ::asio::ip::address_v6{address.to_v6().to_bytes(), scope_id}};
                             }),
                             port());
        }
    }
}

inline bool Endpoint::is_v6() const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    return call_on_base_address([](auto const& address) { return address.is_v6(); });
}

inline bool Endpoint::is_v4() const
{
    assert(is_valid());
    assert(is_udp() || is_tcp());
    return call_on_base_address([](auto const& address) { return address.is_v4(); });
}

inline bool Endpoint::is_udp() const
{
    return (m_protocol == Transport_protocol::udp);
}

inline bool Endpoint::is_tcp() const
{
    return (m_protocol == Transport_protocol::tcp);
}

inline bool Endpoint::is_multicast() const
{
    assert(is_valid());
    return call_on_base_address([](auto const& address) { return address.is_multicast(); });
}

inline bool Endpoint::is_valid() const
{
    return (m_protocol != Transport_protocol::none);
}

inline Endpoint::operator bool() const
{
    return is_valid();
}

inline Transport_protocol Endpoint::transport_protocol() const
{
    return m_protocol;
}

inline bool Endpoint::operator==(Endpoint const& other) const
{
    bool result;
    if (other.m_protocol == m_protocol) {
        switch (m_protocol) {
        case Transport_protocol::udp: {
            result = m_endpoint.udp == other.m_endpoint.udp;
            break;
        }
        case Transport_protocol::tcp: {
            result = m_endpoint.tcp == other.m_endpoint.tcp;
            break;
        }
        default:
            // Transport_protocol::none
            result = false;
            break;
        }
    }
    else {
        result = false;
    }

    return result;
}

inline bool Endpoint::operator<(Endpoint const& other) const
{
    bool result;
    if (other.m_protocol == m_protocol) {
        switch (m_protocol) {
        case Transport_protocol::udp: {
            result = m_endpoint.udp < other.m_endpoint.udp;
            break;
        }
        case Transport_protocol::tcp: {
            result = m_endpoint.tcp < other.m_endpoint.tcp;
            break;
        }
        default:
            // Transport_protocol::none
            result = false;
            break;
        }
    }
    else {
        result = m_protocol < other.m_protocol;
    }
    return result;
}

inline Endpoint_udp const& Endpoint::get_udp_base() const
{
    assert(is_valid());
    assert(is_udp());
    return m_endpoint.udp;
}

inline Endpoint_tcp const& Endpoint::get_tcp_base() const
{
    assert(is_valid());
    assert(is_tcp());
    return m_endpoint.tcp;
}

// Private API implementation
inline void Endpoint::init_ip_endpoint(::asio::ip::address const& ip_address, std::uint16_t port)
{
    if (m_protocol == Transport_protocol::udp) {
        m_endpoint.udp = Endpoint_udp(ip_address, port);
    }
    else {
        assert(m_protocol == Transport_protocol::tcp);
        // check if address is a multicast address
        if (ip_address.is_multicast()) {
            m_protocol = Transport_protocol::none; // invalid endpoint
        }
        else {
            m_endpoint.tcp = Endpoint_tcp(ip_address, port);
        }
    }
}

template<typename Iterator>
inline void Endpoint::init_ip_endpoint(Iterator const& begin, Iterator const& end,
                                       std::uint16_t port, Scope_id scope,
                                       std::random_access_iterator_tag /* tag */)
{
    const auto size = std::distance(begin, end);
    const size_t size_value = (size < 0) ? 0U : static_cast<size_t>(size);
    if (size_value == std::tuple_size<::asio::ip::address_v4::bytes_type>::value) {
        init_ip_endpoint(
            ::asio::ip::address_v4{
                *reinterpret_cast<::asio::ip::address_v4::bytes_type const*>(&*begin)},
            port);
    }
    else if (size_value == std::tuple_size<::asio::ip::address_v6::bytes_type>::value) {
        init_ip_endpoint(
            ::asio::ip::address_v6{
                *reinterpret_cast<::asio::ip::address_v6::bytes_type const*>(&*begin), scope},
            port);
    }
    else {
        m_protocol = Transport_protocol::none;
    }
}

template<typename IpAddressType>
inline void Endpoint::init_ip_endpoint(IpAddressType ip_address, std::uint16_t port)
{
    init_ip_endpoint(::asio::ip::address{std::move(ip_address)}, port);
}

inline void Endpoint::copy_endpoint_base(Endpoint const& other)
{
    if (m_protocol == Transport_protocol::udp) {
        m_endpoint.udp = other.m_endpoint.udp;
    }
    else if (m_protocol == Transport_protocol::tcp) {
        m_endpoint.tcp = other.m_endpoint.tcp;
    }
    else {
        // The endpoint is invalid therefore no endpoint_base needs to be copy
    }
}

inline void Endpoint::move_endpoint_base(Endpoint&& other)
{
    if (m_protocol == Transport_protocol::udp) {
        m_endpoint.udp = std::move(other.m_endpoint.udp);
    }
    else if (m_protocol == Transport_protocol::tcp) {
        m_endpoint.tcp = std::move(other.m_endpoint.tcp);
    }
    else {
        // The endpoint is invalid therefore no endpoint_base needs to be moved
    }
}

inline void Endpoint::destruct_endpoint_base()
{
    if (m_protocol == Transport_protocol::udp) {
        m_endpoint.udp.~Endpoint_udp();
    }
    else if (m_protocol == Transport_protocol::tcp) {
        m_endpoint.tcp.~Endpoint_tcp();
    }
    else {
        // The endpoint is invalid therefore no endpoint_base needs to be destoyed
    }
}

inline ::asio::ip::address_v4::bytes_type
    Endpoint::get_address_bytes(Internet_protocol::Ipv4_tag /* tag */) const
{
    return call_on_base_address(
        [](auto const& address) { return internal::get_ipv4_bytes(address); });
}

inline ::asio::ip::address_v6::bytes_type
    Endpoint::get_address_bytes(Internet_protocol::Ipv6_tag /* tag */) const
{
    return call_on_base_address(
        [](auto const& address) { return internal::get_ipv6_bytes(address); });
}

///   Returns the base type (asio type) of an endpoint.
/// \return Base type (asio type) of an endpoint.
template<typename T>
T const& get_endpoint_base(Endpoint const&);

template<>
inline Endpoint_udp const& get_endpoint_base<Endpoint_udp>(Endpoint const& endpoint)
{
    return endpoint.get_udp_base();
}
template<>
inline Endpoint_tcp const& get_endpoint_base<Endpoint_tcp>(Endpoint const& endpoint)
{
    return endpoint.get_tcp_base();
}

///  Stream output using to_string() returned value.
/// \return std::ostream with to_string() value appended.
inline std::ostream& operator<<(std::ostream& os, Endpoint const& value)
{
    return os << value.to_string();
}
} // namespace net


#endif