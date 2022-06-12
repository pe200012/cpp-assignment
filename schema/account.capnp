@0xa0749fda2e1395fd;
using DataI = import "data.capnp";

enum Permission {
    administrator @0;
    normal @1;
}

struct Student {
    uid @0 :Text;
    password @1 :Text;         # encrypted by SHA256
    name @2 :Text;
    major @3 :Text;
    course @4 :List(DataI.Course);
}

struct Teacher {
    uid @0 :Text;
    password @1 :Text;         # encrypted by SHA256
    name @2 :Text;
    department @3 :Text;
    course @4 :List(DataI.Course);
}

