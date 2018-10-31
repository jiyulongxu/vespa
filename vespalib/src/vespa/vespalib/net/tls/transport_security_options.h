// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#pragma once

#include "certificate_verification_callback.h"
#include <vespa/vespalib/stllike/string.h>
#include <memory>
#include <vector>
#include <iosfwd>

namespace vespalib::net::tls {

// TODO break up and move lots of this stuff out to own files etc

struct HostGlobPattern {
    virtual ~HostGlobPattern() = default;
    virtual bool matches(vespalib::stringref str) const = 0;

    static std::shared_ptr<const HostGlobPattern> create_from_glob(vespalib::stringref pattern);
};

struct RequiredPeerCredential {
    enum class Field {
        CN, SAN_DNS
    };
    Field field;
    vespalib::string original_pattern;
    std::shared_ptr<const HostGlobPattern> match_pattern;

    RequiredPeerCredential() = default;
    RequiredPeerCredential(Field field_, vespalib::string must_match_pattern_);
    ~RequiredPeerCredential();

    bool operator==(const RequiredPeerCredential& rhs) const {
        return ((field == rhs.field)
                 && (original_pattern == rhs.original_pattern));
    }
};

struct PeerPolicy {
    // _all_ credentials must match for the policy itself to match.
    std::vector<RequiredPeerCredential> required_peer_credentials;

    PeerPolicy() = default;
    explicit PeerPolicy(std::vector<RequiredPeerCredential> required_peer_credentials_)
        : required_peer_credentials(std::move(required_peer_credentials_))
    {}

    bool operator==(const PeerPolicy& rhs) const {
        return (required_peer_credentials == rhs.required_peer_credentials);
    }
};

struct AllowedPeers {
    // A peer will be allowed iff it matches _one or more_ policies.
    std::vector<PeerPolicy> peer_policies;

    AllowedPeers() = default;

    explicit AllowedPeers(std::vector<PeerPolicy> peer_policies_)
        : peer_policies(std::move(peer_policies_))
    {}

    bool operator==(const AllowedPeers& rhs) const {
        return (peer_policies == rhs.peer_policies);
    }
};

std::ostream& operator<<(std::ostream&, const RequiredPeerCredential&);
std::ostream& operator<<(std::ostream&, const PeerPolicy&);
std::ostream& operator<<(std::ostream&, const AllowedPeers&);

class TransportSecurityOptions {
    vespalib::string _ca_certs_pem;
    vespalib::string _cert_chain_pem;
    vespalib::string _private_key_pem;
    AllowedPeers     _allowed_peers;
    // TODO set this on context instead?
    std::shared_ptr<CertificateVerificationCallback> _cert_verify_callback;
public:
    TransportSecurityOptions() = default;

    // Construct transport options with a default certificate verification callback
    // which accepts all certificates correctly signed by the given CA(s).
    TransportSecurityOptions(vespalib::string ca_certs_pem,
                             vespalib::string cert_chain_pem,
                             vespalib::string private_key_pem);

    TransportSecurityOptions(vespalib::string ca_certs_pem,
                             vespalib::string cert_chain_pem,
                             vespalib::string private_key_pem,
                             AllowedPeers allowed_peers);

    TransportSecurityOptions(vespalib::string ca_certs_pem,
                             vespalib::string cert_chain_pem,
                             vespalib::string private_key_pem,
                             std::shared_ptr<CertificateVerificationCallback> cert_verify_callback);
    ~TransportSecurityOptions();

    const vespalib::string& ca_certs_pem() const noexcept { return _ca_certs_pem; }
    const vespalib::string& cert_chain_pem() const noexcept { return _cert_chain_pem; }
    const vespalib::string& private_key_pem() const noexcept { return _private_key_pem; }
    const std::shared_ptr<CertificateVerificationCallback>& cert_verify_callback() const noexcept {
        return _cert_verify_callback;
    }
    const AllowedPeers& allowed_peers() const noexcept { return _allowed_peers; }
};

std::unique_ptr<CertificateVerificationCallback> create_verify_callback_from(AllowedPeers allowed_peers);

}
