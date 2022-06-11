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
#include <QString>
#include <QtSql>

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
    QSqlDatabase db;
    redis::Redis redis;
    QRSAEncryption e;
    std::random_device r;

public:
    explicit SystemServerImpl(const QString &host, const QString &database, const QString &username,
                              const QString &password, redis::Redis &&redis) : db(QSqlDatabase::addDatabase("QPSQL")),
                                                                               redis(std::move(redis)),
                                                                               e(QRSAEncryption::Rsa::RSA_2048) {
        db.setHostName(host);
        db.setDatabaseName(database);
        db.setUserName(username);
        db.setPassword(password);
        if (!db.open()) {
            throw "cannot open database";
        }
    }

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
        QSqlQuery statement;
        statement.prepare("SELECT password from accounts where uid = ?;");
        statement.addBindValue(cxt.getParams().getUid().cStr());
        std::string fingerprint = cxt.getParams().getFingerprint();
        statement.exec();
        if (statement.next()) {
            auto maybePubkey = redis.get(fingerprint + "pubkey");
            if (maybePubkey) {
                QByteArray pas, privkey;
                auto pp = *redis.get(fingerprint + "privkey");
                for (const auto &x: cxt.getParams().getPassword()) pas.push_back(x);
                for (const auto &x: pp) privkey.push_back(x);
                std::string passwordSHA = CalcSHA256(e.decode(pas, privkey).toStdString())();
                auto truePassword = statement.value(0).toString().toStdString();
                if (passwordSHA == truePassword) {
                    redis.set(fingerprint + "loginAs", cxt.getParams().getUid().cStr(), std::chrono::minutes(20));
                    redis.expire(fingerprint + "pubkey", std::chrono::minutes(20));
                    redis.expire(fingerprint + "privkey", std::chrono::minutes(20));
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
        redis.del(fingerprint + "pubkey");
        redis.del(fingerprint + "privkey");
        redis.del(fingerprint + "loginAs");
        KJ_LOG(INFO, ("logging out: " + fingerprint));
        return kj::READY_NOW;
    }

    template<typename Context>
    void withLogin(Context &cxt, const std::function<void(const std::string &)> &cont,
                   const std::function<void(void)> &handler) {
        std::string fingerprint = cxt.getParams().getFingerprint();
        auto user = redis.get(fingerprint + "loginAs");
        if (user) {
            cont(*user);
        } else {
            handler();
        }
    }

    kj::Promise<void> upload(UploadContext cxt) override {
        cxt.getResults().setError("");
        withLogin(cxt, [&](auto trueUser) {
            std::string path = cxt.getParams().getPath();
            std::string local = trueUser + "/" + path;
            std::filesystem::create_directories(local);
            std::string tmpname = "tmp.zip";
            std::ofstream outFile(tmpname);
            auto buf = cxt.getParams().getData();
            for (const auto &x: buf) {
                outFile << x;
            }
            outFile.close();
            JlCompress::extractDir(QString::fromStdString(tmpname), QString::fromStdString(local));

            QSqlQuery statement;
            statement.prepare("SELECT counter FROM accounts where uid = ?;");
            statement.addBindValue(trueUser.c_str());
            statement.exec();
            statement.next();
            const int counter = statement.value(0).toInt();
            statement.prepare("UPDATE accounts SET counter = counter + 1 where uid = ?;");
            statement.addBindValue(trueUser.c_str());
            statement.exec();
            statement.prepare("INSERT INTO projects VALUES(?, ?, ?);");
            statement.addBindValue(&counter);
            statement.addBindValue(cxt.getParams().getName().cStr());
            statement.addBindValue(trueUser.c_str());
            statement.exec();
        }, [&cxt]() {
            cxt.getResults().setError("please login first");
        });
        return kj::READY_NOW;
    }

    kj::Promise<void> listProject(ListProjectContext cxt) override {
        ::capnp::MallocMessageBuilder msg;
        withLogin(cxt, [&](auto user) {
            QSqlQuery statement;
            statement.prepare("SELECT name FROM projects WHERE user = ?;");
            statement.addBindValue(user.c_str());
            statement.exec();
            auto result = msg.initRoot<Either<BoxedText, ::capnp::List<Project>>>();
            auto ls = result.initRight(statement.size());
            int i = 10;
            while (statement.next()) {
                ls[i].setName(statement.value(0).toString().toStdString());
                ++i;
            }
            cxt.getResults().setResult(result);
        }, [&]() {
            auto either = msg.initRoot<Either<BoxedText, ::capnp::List<Project>>>();
            auto err = msg.initRoot<BoxedText>();
            err.setValue("please login first");
            either.setLeft(err);
            cxt.getResults().setResult(either);
        });
        return kj::READY_NOW;
    }
};

int main() {
    capnp::EzRpcServer server(kj::heap<SystemServerImpl>("localhost", "myDatabaseName", "postgres", "114514",
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
