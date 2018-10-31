// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include "transport_security_options.h"
#include "peer_credentials.h"
#include <openssl/crypto.h>
#include <cassert>
#include <iostream>
#include <regex>

namespace vespalib::net::tls {

TransportSecurityOptions::TransportSecurityOptions(vespalib::string ca_certs_pem,
                                                   vespalib::string cert_chain_pem,
                                                   vespalib::string private_key_pem)
    : _ca_certs_pem(std::move(ca_certs_pem)),
      _cert_chain_pem(std::move(cert_chain_pem)),
      _private_key_pem(std::move(private_key_pem)),
      _allowed_peers(),
      _cert_verify_callback(std::make_shared<AcceptAllPreVerifiedCertificates>())
{
}

TransportSecurityOptions::TransportSecurityOptions(vespalib::string ca_certs_pem,
                                                   vespalib::string cert_chain_pem,
                                                   vespalib::string private_key_pem,
                                                   AllowedPeers allowed_peers)
        : _ca_certs_pem(std::move(ca_certs_pem)),
          _cert_chain_pem(std::move(cert_chain_pem)),
          _private_key_pem(std::move(private_key_pem)),
          _allowed_peers(std::move(allowed_peers)),
          _cert_verify_callback(std::make_shared<AcceptAllPreVerifiedCertificates>())
{
}

TransportSecurityOptions::TransportSecurityOptions(vespalib::string ca_certs_pem,
                                                   vespalib::string cert_chain_pem,
                                                   vespalib::string private_key_pem,
                                                   std::shared_ptr<CertificateVerificationCallback> cert_verify_callback)
        : _ca_certs_pem(std::move(ca_certs_pem)),
          _cert_chain_pem(std::move(cert_chain_pem)),
          _private_key_pem(std::move(private_key_pem)),
          _allowed_peers(),
          _cert_verify_callback(std::move(cert_verify_callback))
{
    assert(_cert_verify_callback);
}

TransportSecurityOptions::~TransportSecurityOptions() {
    OPENSSL_cleanse(&_private_key_pem[0], _private_key_pem.size());
}

std::ostream& operator<<(std::ostream& os, const RequiredPeerCredential& cred) {
    os << "RequiredPeerCredential("
       << (cred.field == RequiredPeerCredential::Field::CN ? "CN" : "SAN")
       << " matches '"
       << cred.original_pattern
       << "')";
    return os;
}

std::ostream& operator<<(std::ostream& os, const PeerPolicy& policy) {
    os << "PeerPolicy(";
    for (auto& cred : policy.required_peer_credentials) {
        os << cred;
    }
    os << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, const AllowedPeers& allowed){
    os << "AllowedPeers(\n";
    for (auto& p : allowed.peer_policies) {
        os << p << "\n";
    }
    os << ")";
    return os;
}

namespace {

// Note: this is for basix regexp only, _not_ extended regexp
bool is_basic_regex_special_char(char c) noexcept {
    switch (c) {
    case '^':
    case '$':
    case '.':
    case '[':
    case '\\':
        return true;
    default:
        return false;
    }
}

std::string glob_to_regex(vespalib::stringref glob) {
    std::string ret = "^";
    ret.reserve(glob.size() + 2);
    for (auto c : glob) {
        if (c == '*') {
            // Note: we explicitly stop matching at a dot separator boundary.
            // This is to make host name matching less vulnerable to dirty tricks.
            ret += "[^.]*";
        } else if (c == '?') {
            // Same applies for single chars; they should only match _within_ a dot boundary.
            ret += "[^.]";
        } else {
            if (is_basic_regex_special_char(c)) {
                ret += '\\';
            }
            ret += c;
        }
    }
    ret += '$';
    return ret;
}

struct RegexMatchPattern : HostGlobPattern {
    std::regex _pattern_as_regex;

    explicit RegexMatchPattern(vespalib::stringref glob_pattern)
        : _pattern_as_regex(glob_to_regex(glob_pattern), std::regex_constants::basic)
    {
    }
    ~RegexMatchPattern() override = default;

    bool matches(vespalib::stringref str) const override {
        return std::regex_match(str.begin(), str.end(), _pattern_as_regex);
    }
};

bool matches_single_san_requirement(const PeerCredentials& peer_creds, const RequiredPeerCredential& requirement) {
    for (auto& provided_cred : peer_creds.dns_sans) {
        if (requirement.match_pattern->matches(provided_cred)) {
            return true;
        }
    }
    return false;
}

bool matches_all_policy_requirements(const PeerCredentials& peer_creds, const PeerPolicy& policy) {
    for (auto& required_cred : policy.required_peer_credentials) {
        switch (required_cred.field) {
        case RequiredPeerCredential::Field::SAN_DNS:
            if (!matches_single_san_requirement(peer_creds, required_cred)) {
                return false;
            }
            continue;
        case RequiredPeerCredential::Field::CN:
            return false; // TODO
        }
        abort();
    }
    return true;
}

}

RequiredPeerCredential::RequiredPeerCredential(Field field_, vespalib::string must_match_pattern_)
    : field(field_),
      original_pattern(std::move(must_match_pattern_)),
      match_pattern(HostGlobPattern::create_from_glob(original_pattern))
{
}

RequiredPeerCredential::~RequiredPeerCredential() = default;

std::shared_ptr<const HostGlobPattern> HostGlobPattern::create_from_glob(vespalib::stringref glob_pattern) {
    return std::make_shared<const RegexMatchPattern>(glob_pattern);
}

class PolicyConfiguredCertificateVerifier : public CertificateVerificationCallback {
    AllowedPeers _allowed_peers;
public:
    explicit PolicyConfiguredCertificateVerifier(AllowedPeers allowed_peers);
    ~PolicyConfiguredCertificateVerifier() override;

    bool verify(const PeerCredentials& peer_creds) const override;
};

PolicyConfiguredCertificateVerifier::PolicyConfiguredCertificateVerifier(AllowedPeers allowed_peers)
    : _allowed_peers(std::move(allowed_peers))
{}

PolicyConfiguredCertificateVerifier::~PolicyConfiguredCertificateVerifier() = default;

bool PolicyConfiguredCertificateVerifier::verify(const PeerCredentials& peer_creds) const {
    for (auto& policy : _allowed_peers.peer_policies) {
        if (matches_all_policy_requirements(peer_creds, policy)) {
            return true;
        }
    }
    return false;
}

std::unique_ptr<CertificateVerificationCallback> create_verify_callback_from(AllowedPeers allowed_peers) {
    return std::make_unique<PolicyConfiguredCertificateVerifier>(std::move(allowed_peers));
}

}
