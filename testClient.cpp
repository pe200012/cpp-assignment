//
// Created by pe200012 on 22/06/06.
//
#include <iostream>
#include <array>
#include <fstream>
#include <iterator>
#include <vector>
#include <capnp/message.h>
#include <capnp/ez-rpc.h>
#include "system.capnp.h"
#include "qrsaencryption.h"
#include "third_party/Base64.h"
#include "SHA256.h"
#include <QuaZip-Qt5-1.3/quazip/JlCompress.h>

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

class Client {
    capnp::EzRpcClient client;
    QByteArray pubkey;
    std::string fingerprint;
    System::Client system;
    kj::WaitScope &scope;
    QRSAEncryption e;
    std::string name;

    void init() {
        auto pack = system.initiateSessionRequest().send().wait(scope).getPack();
        fingerprint = pack.getFingerprint();
        auto pubkeyPtr = pack.getPubkey();
        pubkey.clear();
        for (const auto &x: pubkeyPtr) pubkey.push_back(x);
    }

public:
    Client(const std::string &host, const int port) : client(host, port), system(client.getMain<System>()),
                                                      scope(client.getWaitScope()), e(QRSAEncryption::Rsa::RSA_2048) {
        init();
    }

    bool login(const std::string &username, const std::string &password) {
        QByteArray buf(password.c_str());
        auto enc = e.encode(buf, pubkey);
        auto req = system.loginRequest();
        req.setUid(username);
        uint8_t bytes[enc.size()];
        for (int i = 0; i != enc.size(); ++i) bytes[i] = enc[i];
        auto payload = kj::arrayPtr(bytes, sizeof(bytes));
        req.setFingerprint(fingerprint);
        req.setPassword(payload);
        std::string err = req.send().wait(scope).getError();
        if (!err.empty()) {
            std::cerr << "login failed: " << err << std::endl;
            return false;
        } else {
            name = username;
            return true;
        }
    }

    void logout() {
        if (!fingerprint.empty()) {
            auto req = system.logoutRequest();
            req.setFingerprint(fingerprint);
            req.send().wait(scope);
            fingerprint.clear();
        }
    }

    void upload(std::string name, std::string path, std::string remotePath) {
        JlCompress::compressDir(QString::fromStdString(name + ".zip"), QString::fromStdString(path));
        std::ifstream input(name + ".zip", std::ios::binary);
        std::vector<uint8_t> bytes(
                (std::istreambuf_iterator<char>(input)),
                (std::istreambuf_iterator<char>()));
        input.close();
        uint8_t buf[bytes.size()];
        for (int i = 0; i != bytes.size(); ++i) buf[i] = bytes[i];
        auto payload = kj::arrayPtr(buf, bytes.size());
        auto req = system.uploadRequest();
        req.setFingerprint(fingerprint);
        req.setName(name);
        req.setPath(remotePath);
        req.setData(payload);
        std::string err = req.send().wait(scope).getError();
        if (!err.empty()) {
            std::cerr << err << std::endl;
        }
    }
    void listProject() {
        auto req = system.listProjectRequest();
        req.setFingerprint(fingerprint);
        auto result = req.send().wait(scope).getResult();
        if (result.hasLeft()) {
            std::cerr<<result.getLeft().getValue().cStr()<<std::endl;
        } else {
            auto ls = result.getRight();
            for (const auto &x: ls) {
                std::cout << x.getName().cStr() << std::endl;
            }
        }
    }
};

int main(void) {
    Client c("localhost", 10100);
    c.login("user1", "password");
    c.upload("proj1", "./design_dir", "design_dir");
    c.listProject();
    c.logout();
    return 0;
}
