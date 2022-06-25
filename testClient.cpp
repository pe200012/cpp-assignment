//
// Created by pe200012 on 22/06/06.
//
#include "SHA256.h"
#include <qrsaencryption.h>
#include "system.capnp.h"
#include "third_party/Base64.h"
#include <QuaZip-Qt5-1.3/quazip/JlCompress.h>
#include <array>
#include <capnp/ez-rpc.h>
#include <capnp/message.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

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

    std::string operator()() const noexcept { return s; }
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
        for (const auto &x: pubkeyPtr)
            pubkey.push_back(x);
    }

public:
    Client(const std::string &host, const int port)
            : client(host, port), system(client.getMain<System>()),
              scope(client.getWaitScope()), e(QRSAEncryption::Rsa::RSA_2048) {
        init();
    }

    bool login(const std::string &username, const std::string &password) {
        QByteArray buf(password.c_str());
        auto enc = e.encode(buf, pubkey);
        auto req = system.loginRequest();
        req.setUid(username);
        uint8_t bytes[enc.size()];
        for (int i = 0; i != enc.size(); ++i)
            bytes[i] = enc[i];
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

    void upload(const std::string &name, const std::string &path,
                const std::string &remotePath) {
        JlCompress::compressDir(QString::fromStdString(name + ".zip"),
                                QString::fromStdString(path));
        std::ifstream input(name + ".zip", std::ios::binary);
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),
                                   (std::istreambuf_iterator<char>()));
        input.close();
        uint8_t buf[bytes.size()];
        for (int i = 0; i != bytes.size(); ++i)
            buf[i] = bytes[i];
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

    void remove(const std::string &projectId) {
        auto req = system.removeRequest();
        req.setFingerprint(fingerprint);
        req.setPid(projectId);
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
            std::cerr << result.getLeft().getValue().cStr() << std::endl;
        } else {
            auto ls = result.getRight();
            for (const auto &x: ls) {
                std::cout << x.getId() << ':' << x.getName().cStr() << std::endl;
            }
        }
    }

    void listAll() {
        auto req = system.listAllRequest();
        req.setFingerprint(fingerprint);
        auto result = req.send().wait(scope).getResult();
        if (result.hasLeft()) {
            std::cerr << result.getLeft().getValue().cStr() << std::endl;
        } else {
            auto ls = result.getRight();
            for (const auto &x: ls) {
                std::cout << x.getId() << ':' << x.getName().cStr() << std::endl;
            }
        }
    }

    void addStudent(const std::string &uid, const std::string &courseName) {
        auto req = system.addStudentRequest();
        req.setFingerprint(fingerprint);
        req.setUid(uid);
        req.setCourseName(courseName);
        std::string result = req.send().wait(scope).getError();
        if (!result.empty()) {
            std::cout << result << std::endl;
        }
    }

    void removeStudent(const std::string &uid, const std::string &courseName) {
        auto req = system.removeStudentRequest();
        req.setFingerprint(fingerprint);
        req.setUid(uid);
        req.setCourseName(courseName);
        std::string result = req.send().wait(scope).getError();
        if (!result.empty()) {
            std::cout << result << std::endl;
        }
    }

    void judge(const std::string &id, const double score) {
        auto req = system.judgeRequest();
        req.setFingerprint(fingerprint);
        req.setId(id);
        req.setScore(score);
        std::string result = req.send().wait(scope).getError();
        if (!result.empty()) {
            std::cout << result << std::endl;
        }
    }

    void newCourse(const std::string &courseName) {
        auto req = system.newCourseRequest();
        req.setFingerprint(fingerprint);
        req.setCourseName(courseName);
        std::string result = req.send().wait(scope).getError();
        if (!result.empty()) {
            std::cout << result << std::endl;
        }
    }

    void deleteCourse(const std::string &courseId) {
        auto req = system.deleteCourseRequest();
        req.setFingerprint(fingerprint);
        req.setCourseId(courseId);
        std::string result = req.send().wait(scope).getError();
        if (!result.empty()) {
            std::cout << result << std::endl;
        }
    }
};

void formLoop() {
    Client c("localhost", 10100);
    std::cout << "==================================" << std::endl;
    std::cout << "=        毕业设计管理系统          =" << std::endl;
    std::cout << "==================================" << std::endl;
    std::string username, password;
    while (true) {
        std::cout << "登录用户名: " << std::flush;
        std::cin >> username;
        std::cout << "用户密码: " << std::flush;
        std::cin >> password;
        if (!c.login(username, password)) { ;
            std::cout << std::endl;
        } else {
            std::cout << "登录成功!" << std::endl;
            break;
        }
    }
    bool flag = true;
    while (flag) {
        std::cout << "0) 退出" << std::endl;
        std::cout << "1) 上传课程设计" << std::endl;
        std::cout << "2) 删除课程设计" << std::endl;
        std::cout << "3) 列出我的课程设计" << std::endl;
        std::cout << "4) 列出所有课程设计" << std::endl;
        std::cout << "5) 添加学生到课程" << std::endl;
        std::cout << "6) 从课程删除学生" << std::endl;
        std::cout << "7) 给项目评分" << std::endl;
        std::cout << "8) 添加课程" << std::endl;
        std::cout << "9) 删除课程" << std::endl;
        std::cout << "choice: " << std::flush;
        int choice;
        std::cin >> choice;
        std::string projectName, path, remotePath, student, courseName;
        switch (choice) {
            case 0:
                flag = false;
                break;
            case 1:
                std::cout << "项目名称： " << std::flush;
                std::cin >> projectName;
                std::cout << "项目路径： " << std::flush;
                std::cin >> path;
                std::cout << "远端路径： " << std::flush;
                std::cin >> remotePath;
                c.upload(projectName, path, remotePath);
                std::cout << "完成操作" << std::endl;
                break;
            case 2:
                std::cout << "项目编号： " << std::flush;
                std::cin >> projectName;
                c.remove(projectName);
                std::cout << "完成操作" << std::endl;
            case 3:
                std::cout << "我的课程设计:" << std::endl;
                c.listProject();
                break;
            case 4:
                std::cout << "课程设计:" << std::endl;
                c.listAll();
                break;
            case 5:
                std::cout << "课程名称： " << std::flush;
                std::cin >> courseName;
                std::cout << "学生姓名： " << std::flush;
                std::cin >> student;
                c.addStudent(courseName, student);
                std::cout << "完成操作" << std::endl;
                break;
            case 6:
                std::cout << "课程名称： " << std::flush;
                std::cin >> courseName;
                std::cout << "学生姓名： " << std::flush;
                std::cin >> student;
                c.removeStudent(courseName, student);
                std::cout << "完成操作" << std::endl;
                break;
            case 7:
                std::cout << "项目编号： " << std::flush;
                std::cin >> projectName;
                std::cout << "评分： " << std::flush;
                double score;
                std::cin >> score;
                c.judge(projectName, score);
                std::cout << "完成操作" << std::endl;
                break;
            case 8:
                std::cout << "课程名称： " << std::flush;
                std::cin >> courseName;
                c.newCourse(courseName);
                std::cout << "完成操作" << std::endl;
                break;
            case 9:
                std::cout << "课程名称： " << std::flush;
                std::cin >> courseName;
                c.deleteCourse(courseName);
                std::cout << "完成操作" << std::endl;
                break;

            default:;
        }
    }
}

int main(void) {
    formLoop();
    return 0;
}
