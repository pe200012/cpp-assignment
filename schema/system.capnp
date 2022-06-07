@0x9debc8d208d4181b;

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
    upload @2 (fingerprint :Fingerprint, path :Text, data :Data) -> (error :Text);
    remove @3 (fingerprint :Fingerprint, name :Text) -> (error :Text);
}
