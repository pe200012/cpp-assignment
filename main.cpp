#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <nanodbc/nanodbc.h>
#include <capnp/message.h>
#include <capnp/ez-rpc.h>
#include <kj/debug.h>
#include <kj/exception.h>
#include "account.capnp.h"
#include "system.capnp.h"
#include "SHA256.h"
#include "third_party/Base64.h"
#include <qrsaencryption.h>
#include <sw/redis++/redis++.h>
#include <QuaZip-Qt5-1.3/quazip/JlCompress.h>

using namespace sw;

class CalcSHA256 {
    std::string s;
public:
    CalcSHA256(std::string msg) {
        SHA256 sha;
        sha.update(msg);
        auto *digest = sha.digest();
        s = SHA256::toString(digest);
        delete[] digest;
    }

    std::string operator()() const {
        return s;
    }
};

class SystemServerImpl final : public System::Server {
    nanodbc::connection conn;
    redis::Redis redis;
    QRSAEncryption e;
    std::random_device r;

public:
    explicit SystemServerImpl(const std::string &connstr, redis::Redis &&redis) : conn(connstr),
                                                                                  redis(std::move(redis)),
                                                                                  e(QRSAEncryption::Rsa::RSA_2048) {}

    kj::Promise<void> initiateSession(InitiateSessionContext cxt) override {
        ::capnp::MallocMessageBuilder msg;
        std::default_random_engine e1(r());
        std::uniform_int_distribution<char> dist('A', 'Z');
        std::string newFingerprint;
        KJ_LOG(INFO, "Generating new fingerprint...");
        for (int i = 0; i != 64; ++i) {
            newFingerprint += dist(e1);
        }
        KJ_LOG(INFO, "Generating new RSA pair...");
        QByteArray pub, priv;
        e.generatePairKey(pub, priv);
        redis.set(newFingerprint + "pubkey", pub.toStdString(), std::chrono::minutes(20));
        redis.set(newFingerprint + "privkey", priv.toStdString(), std::chrono::minutes(20));
        auto pack = msg.initRoot<InitPack>();
        pack.setFingerprint(newFingerprint);
        uint8_t bytes[pub.size()];
        for (int i = 0; i != pub.size(); ++i) bytes[i] = pub[i];
        auto ptr = kj::arrayPtr(bytes, pub.size());
        pack.setPubkey(ptr);
        cxt.getResults().setPack(pack);
        return kj::READY_NOW;
    }

    kj::Promise<void> login(LoginContext cxt) override {
        cxt.getResults().setError("");
        nanodbc::statement statement(conn);
        prepare(statement, "SELECT password from accounts where uid = ?;");
        statement.bind(0, cxt.getParams().getUid().cStr());
        std::string fingerprint = cxt.getParams().getFingerprint();
        auto result = nanodbc::execute(statement);
        if (result.next()) {
            auto maybePubkey = redis.get(fingerprint + "pubkey");
            if (maybePubkey) {
                QByteArray pas, privkey;
                auto pp = *redis.get(fingerprint+"privkey");
                for (const auto &x: cxt.getParams().getPassword()) pas.push_back(x);
                for (const auto &x: pp) privkey.push_back(x);
                std::string passwordSHA = CalcSHA256(e.decode(pas, privkey).toStdString())();
                auto truePassword = result.get<std::string>(0);
                if (passwordSHA == truePassword) {
                    redis.set(fingerprint+"loginAs", cxt.getParams().getUid().cStr(), std::chrono::minutes(20));
                    redis.expire(fingerprint+"pubkey", std::chrono::minutes(20));
                    redis.expire(fingerprint+"privkey", std::chrono::minutes(20));
                    return kj::READY_NOW;
                } else {
                    cxt.getResults().setError("incorrect password");
                }
            } else {
                cxt.getResults().setError("session not initiated or expired");
            }
        } else {
            cxt.getResults().setError("non-existent account");
        }
        return kj::READY_NOW;
    }
    kj::Promise<void> logout(LogoutContext cxt) override {
        std::string fingerprint = cxt.getParams().getFingerprint();
        redis.del(fingerprint+"pubkey");
        redis.del(fingerprint+"privkey");
        redis.del(fingerprint+"loginAs");
        KJ_LOG(INFO, ("logging out: " + fingerprint));
        return kj::READY_NOW;
    }
    kj::Promise<void> upload(UploadContext cxt) override {
        std::string fingerprint = cxt.getParams().getFingerprint();
        auto user = redis.get(fingerprint+"loginAs");
        if (user) {
            std::string path = cxt.getParams().getPath();
            std::string local = (*user) + "/" + path;
            std::filesystem::create_directories(local);
            std::ofstream outFile("tmp.zip");
            auto buf = cxt.getParams().getData();
            for (const auto &x : buf) {
                outFile << x;
            }
            outFile.close();
            JlCompress::extractDir("tmp.zip", QString::fromStdString(local));
        } else {
            cxt.getResults().setError("please login first");
        }
        return kj::READY_NOW;
    }
};

int main() {
    capnp::EzRpcServer server(kj::heap<SystemServerImpl>("Driver={PostgreSQL Unicode};DATABASE=myDatabaseName;",
                                                         redis::Redis("tcp://127.0.0.1:6379")), "*:10100");
    ::kj::_::Debug::setLogLevel(kj::LogSeverity::INFO);
    auto &scope = server.getWaitScope();
    unsigned int port = server.getPort().wait(scope);
    if (!port) {
        std::cout << "Listening on UNIX socket..." << std::endl;
    } else {
        std::cout << "Listening on port " << port << std::endl;
    }
    kj::NEVER_DONE.wait(scope);
    return 0;
}
