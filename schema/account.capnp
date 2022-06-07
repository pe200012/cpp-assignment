@0xa0749fda2e1395fd;

enum Permission {
    administrator @0;
    normal @1;
}

struct Account {
    uid @0 :Text;
    permission @1 :Permission;
    password @2 :Text;         # encrypted by SHA256
}
