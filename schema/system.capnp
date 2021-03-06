@0x9debc8d208d4181b;
using DataI = import "data.capnp";

struct BoxedText {
    value @0 :Text;
}

struct Either(A, B) {
    union {
        left @0 : A;
        right @1 : B;
    }
}

struct InitPack {
    fingerprint @0 :Text;
    pubkey @1 :Data;
}

interface System {
    using Fingerprint = Text;
    initiateSession @4 () -> (pack :InitPack);
    login @0 (fingerprint :Fingerprint, uid :Text, password :Data) -> (error :Text);
    logout @1 (fingerprint :Fingerprint) -> ();
    upload @2 (fingerprint :Fingerprint, name :Text, path :Text, data :Data) -> (error :Text);
    remove @3 (fingerprint :Fingerprint, pid :Text) -> (error :Text);
    listProject @5 (fingerprint :Fingerprint) -> (result :Either(BoxedText, List(DataI.Project)));
    listAll @6 (fingerprint :Fingerprint, courseName :Text) -> (result :Either(BoxedText, List(DataI.Project)));
    addStudent @7 (fingerprint :Fingerprint, uid :Text, courseName :Text) -> (error :Text);
    removeStudent @8 (fingerprint :Fingerprint, uid :Text, courseName :Text) -> (error :Text);
    judge @9 (fingerprint :Fingerprint, id :Text, score :Float32) -> (error :Text);
    newCourse @10 (fingerprint :Fingerprint, courseName :Text) -> (error :Text);
    deleteCourse @11 (fingerprint :Fingerprint, courseId :Text) -> (error :Text);
}
