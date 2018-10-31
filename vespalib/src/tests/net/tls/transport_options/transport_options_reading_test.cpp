// Copyright 2018 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
#include <vespa/vespalib/io/fileutil.h>
#include <vespa/vespalib/net/tls/transport_security_options.h>
#include <vespa/vespalib/net/tls/transport_security_options_reading.h>
#include <vespa/vespalib/testkit/test_kit.h>
#include <vespa/vespalib/util/exceptions.h>

using namespace vespalib;
using namespace vespalib::net::tls;

TEST("can load TLS credentials via config file") {
    auto opts = read_options_from_json_file("ok_config.json");
    ASSERT_TRUE(opts.get() != nullptr);
    // Obviously we'd need to change this to actual PEM data if config reading started
    // actually verifying the _content_ of files, not just reading them.
    EXPECT_EQUAL("My private key\n", opts->private_key_pem());
    EXPECT_EQUAL("My CA certificates\n", opts->ca_certs_pem());
    EXPECT_EQUAL("My certificate chain\n", opts->cert_chain_pem());
}

TEST("missing JSON file throws exception") {
    EXPECT_EXCEPTION(read_options_from_json_file("missing_config.json"), IllegalArgumentException,
                     "TLS config file 'missing_config.json' could not be read");
}

TEST("bad JSON content throws exception") {
    const char* bad_json = "hello world :D";
    EXPECT_EXCEPTION(read_options_from_json_string(bad_json), IllegalArgumentException,
                     "Provided TLS config file is not valid JSON");
}

TEST("missing 'files' field throws exception") {
    const char* incomplete_json = R"({})";
    EXPECT_EXCEPTION(read_options_from_json_string(incomplete_json), IllegalArgumentException,
                     "TLS config root field 'files' is missing or empty");
}

TEST("missing 'private-key' field throws exception") {
    const char* incomplete_json = R"({"files":{"certificates":"dummy_certs.txt","ca-certificates":"dummy_ca_certs.txt"}})";
    EXPECT_EXCEPTION(read_options_from_json_string(incomplete_json), IllegalArgumentException,
                     "TLS config field 'private-key' has not been set");
}

TEST("missing 'certificates' field throws exception") {
    const char* incomplete_json = R"({"files":{"private-key":"dummy_privkey.txt","ca-certificates":"dummy_ca_certs.txt"}})";
    EXPECT_EXCEPTION(read_options_from_json_string(incomplete_json), IllegalArgumentException,
                     "TLS config field 'certificates' has not been set");
}

TEST("missing 'ca-certificates' field throws exception") {
    const char* incomplete_json = R"({"files":{"private-key":"dummy_privkey.txt","certificates":"dummy_certs.txt"}})";
    EXPECT_EXCEPTION(read_options_from_json_string(incomplete_json), IllegalArgumentException,
                     "TLS config field 'ca-certificates' has not been set");
}

TEST("missing file referenced by field throws exception") {
    const char* incomplete_json = R"({"files":{"private-key":"missing_privkey.txt",
                                               "certificates":"dummy_certs.txt",
                                               "ca-certificates":"dummy_ca_certs.txt"}})";
    EXPECT_EXCEPTION(read_options_from_json_string(incomplete_json), IllegalArgumentException,
                     "File 'missing_privkey.txt' referenced by TLS config does not exist");
}

RequiredPeerCredential required_cn(vespalib::stringref pattern) {
    return {RequiredPeerCredential::Field::CN, pattern};
}

RequiredPeerCredential required_san_dns(vespalib::stringref pattern) {
    return {RequiredPeerCredential::Field::SAN_DNS, pattern};
}

PeerPolicy policy_with(std::vector<RequiredPeerCredential> creds) {
    return PeerPolicy(std::move(creds));
}

AllowedPeers allowed_peers(std::vector<PeerPolicy> peer_policies) {
    return AllowedPeers(std::move(peer_policies));
}

vespalib::string json_with_policies(const vespalib::string& policies) {
    const char* fmt = R"({"files":{"private-key":"dummy_privkey.txt",
                                   "certificates":"dummy_certs.txt",
                                   "ca-certificates":"dummy_ca_certs.txt"},
                          "allowed-peers":[%s]})";
    return vespalib::make_string(fmt, policies.c_str());
}

TransportSecurityOptions parse_policies(const vespalib::string& policies) {
    return *read_options_from_json_string(json_with_policies(policies));
}

TEST("can parse single peer policy with single requirement") {
    const char* json = R"({
      "required-credentials":[
         {"field": "SAN_DNS", "must-match": "hello.world"}
      ]
    })";
    EXPECT_EQUAL(allowed_peers({policy_with({required_san_dns("hello.world")})}),
                 parse_policies(json).allowed_peers());
}

TEST("can parse single peer policy with multiple requirements") {
    const char* json = R"({
      "required-credentials":[
         {"field": "SAN_DNS", "must-match": "hello.world"},
         {"field": "CN", "must-match": "goodbye.moon"}
      ]
    })";
    EXPECT_EQUAL(allowed_peers({policy_with({required_san_dns("hello.world"),
                                             required_cn("goodbye.moon")})}),
                 parse_policies(json).allowed_peers());
}

TEST("unknown field type throws exception") {
    const char* json = R"({
      "required-credentials":[
         {"field": "winnie the pooh", "must-match": "piglet"}
      ]
    })";
    EXPECT_EXCEPTION(parse_policies(json), vespalib::IllegalArgumentException,
                     "Unsupported credential field type: 'winnie the pooh'. Supported are: CN, SAN_DNS");
}

// TODO test parsing of multiple policies

bool glob_matches(vespalib::stringref pattern, vespalib::stringref string_to_check) {
    auto glob = HostGlobPattern::create_from_glob(pattern);
    return glob->matches(string_to_check);
}

TEST("glob without wildcards matches entire string") {
    EXPECT_TRUE(glob_matches("foo", "foo"));
    EXPECT_FALSE(glob_matches("foo", "fooo"));
    EXPECT_FALSE(glob_matches("foo", "ffoo"));
}

TEST("wildcard glob can match prefix") {
    EXPECT_TRUE(glob_matches("foo*", "foo"));
    EXPECT_TRUE(glob_matches("foo*", "foobar"));
    EXPECT_FALSE(glob_matches("foo*", "ffoo"));
}

TEST("wildcard glob can match suffix") {
    EXPECT_TRUE(glob_matches("*foo", "foo"));
    EXPECT_TRUE(glob_matches("*foo", "ffoo"));
    EXPECT_FALSE(glob_matches("*foo", "fooo"));
}

TEST("wildcard glob can match substring") {
    EXPECT_TRUE(glob_matches("f*o", "fo"));
    EXPECT_TRUE(glob_matches("f*o", "foo"));
    EXPECT_TRUE(glob_matches("f*o", "ffoo"));
    EXPECT_FALSE(glob_matches("f*o", "boo"));
}

TEST("wildcard glob does not cross multiple dot delimiter boundaries") {
    EXPECT_TRUE(glob_matches("*.bar.baz", "foo.bar.baz"));
    EXPECT_TRUE(glob_matches("*.bar.baz", ".bar.baz"));
    EXPECT_FALSE(glob_matches("*.bar.baz", "zoid.foo.bar.baz"));
    EXPECT_TRUE(glob_matches("foo.*.baz", "foo.bar.baz"));
    EXPECT_FALSE(glob_matches("foo.*.baz", "foo.bar.zoid.baz"));
}

TEST("single char glob matches non dot characters") {
    EXPECT_TRUE(glob_matches("f?o", "foo"));
    EXPECT_FALSE(glob_matches("f?o", "fooo"));
    EXPECT_FALSE(glob_matches("f?o", "ffoo"));
    EXPECT_FALSE(glob_matches("f?o", "f.o"));
}

TEST("special basic regex characters are escaped") {
    EXPECT_TRUE(glob_matches("$[.\\^", "$[.\\^"));
}

TEST("special extended regex characters are ignored") {
    EXPECT_TRUE(glob_matches("{)(+|]}", "{)(+|]}"));
}

// TODO CN
PeerCredentials creds_with_dns_sans(std::vector<vespalib::string> dns_sans) {
    PeerCredentials creds;
    creds.dns_sans = std::move(dns_sans);
    return creds;
}

bool verify(AllowedPeers allowed_peers, const PeerCredentials& peer_creds) {
    auto verifier = create_verify_callback_from(std::move(allowed_peers));
    return verifier->verify(peer_creds);
}

TEST("SAN requirement without glob pattern is matched as exact string") {
    auto allowed = allowed_peers({policy_with({required_san_dns("hello.world")})});
    EXPECT_TRUE(verify(allowed,  creds_with_dns_sans({{"hello.world"}})));
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"foo.bar"}})));
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"hello.worlds"}})));
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"hhello.world"}})));
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"foo.hello.world"}})));
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"hello.world.bar"}})));
}

TEST("multi-SAN policy requires all SANs to be present in certificate") {
    auto allowed = allowed_peers({policy_with({required_san_dns("hello.world"),
                                               required_san_dns("foo.bar")})});
    EXPECT_TRUE(verify(allowed,  creds_with_dns_sans({{"hello.world"}, {"foo.bar"}})));
    // Need both
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"hello.world"}})));
    EXPECT_FALSE(verify(allowed, creds_with_dns_sans({{"foo.bar"}})));
    // OK with more SANs that strictly required
    EXPECT_TRUE(verify(allowed,  creds_with_dns_sans({{"hello.world"}, {"foo.bar"}, {"baz.blorg"}})));
}

struct MultiPolicyMatchFixture {
    AllowedPeers allowed;
    MultiPolicyMatchFixture();
    ~MultiPolicyMatchFixture();
};

MultiPolicyMatchFixture::MultiPolicyMatchFixture()
    : allowed(allowed_peers({policy_with({required_san_dns("hello.world")}),
                             policy_with({required_san_dns("foo.bar")}),
                             policy_with({required_san_dns("zoid.berg")})}))
{}

MultiPolicyMatchFixture::~MultiPolicyMatchFixture() = default;

TEST_F("peer verifies if it matches at least 1 policy of multiple", MultiPolicyMatchFixture) {
    EXPECT_TRUE(verify(f.allowed, creds_with_dns_sans({{"hello.world"}})));
    EXPECT_TRUE(verify(f.allowed, creds_with_dns_sans({{"foo.bar"}})));
    EXPECT_TRUE(verify(f.allowed, creds_with_dns_sans({{"zoid.berg"}})));
}

TEST_F("peer verifies if it matches multiple policies", MultiPolicyMatchFixture) {
    EXPECT_TRUE(verify(f.allowed, creds_with_dns_sans({{"hello.world"}, {"zoid.berg"}})));
}

TEST_F("peer must match at least 1 of multiple policies", MultiPolicyMatchFixture) {
    EXPECT_FALSE(verify(f.allowed, creds_with_dns_sans({{"does.not.exist"}})));
}

TEST_MAIN() { TEST_RUN_ALL(); }

