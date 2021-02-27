//
//  NoiseState.swift
//  Noise
//
//  Created by Carl Dong on 2/27/21.
//

import CryptoKit
import Foundation

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return map { String(format: format, $0) }.joined()
    }
}

extension UInt64 {
    var byteArrayLittleEndian: [UInt8] {
        return [
            UInt8((self & 0xFF00000000000000) >> 56),
            UInt8((self & 0x00FF000000000000) >> 48),
            UInt8((self & 0x0000FF0000000000) >> 40),
            UInt8((self & 0x000000FF00000000) >> 32),
            UInt8((self & 0x00000000FF000000) >> 24),
            UInt8((self & 0x0000000000FF0000) >> 16),
            UInt8((self & 0x000000000000FF00) >> 8),
            UInt8((self & 0x00000000000000FF))
        ]
    }
}

struct CipherState {
    var key: SymmetricKey?;
    var nonce: UInt64 = 0;

    init(fromKey: SymmetricKey) {
        initializeKey(fromKey);
    }

    func getNonce() -> ChaChaPoly.Nonce {
        var bytes = Data.init(count: 4);
        bytes += self.nonce.byteArrayLittleEndian;
        assert(bytes.count == 12);
        return try! ChaChaPoly.Nonce.init(data: bytes);
    }

    mutating func initializeKey(_ key: SymmetricKey) {
        self.key = key;
        self.nonce = 0;
    }

    func hasKey() -> Bool {
        return self.key != nil;
    }

    mutating func encrypt_with_ad<Plaintext, AuthenticatedData>(_ message: Plaintext, authenticating authenticatedData: AuthenticatedData) -> Data where Plaintext : DataProtocol, AuthenticatedData : DataProtocol {
        let rv: Data;
        if let key = self.key {
            let sealedBox = try! ChaChaPoly.seal(message, using: key, nonce: getNonce(), authenticating: authenticatedData);
            rv = sealedBox.combined;
            nonce += 1;
        } else {
            rv = Data(message);
        }
        return rv;
    }

    mutating func decrypt_with_ad<AuthenticatedData>(_ combined: Data, authenticating authenticatedData: AuthenticatedData) -> Data where AuthenticatedData : DataProtocol {
        let rv: Data;
        if let key = self.key {
            let sealedBox = try! ChaChaPoly.SealedBox.init(combined: combined);
            rv = try! ChaChaPoly.open(sealedBox, using: key, authenticating: authenticatedData);
            nonce += 1;
        } else {
            rv = combined
        }
        return rv;
    }

    mutating func write_message_regular(inOut: Data) -> Data {
        return encrypt_with_ad(inOut, authenticating: Data.init());
    }

    mutating func read_message_regular(inOut: Data) -> Data {
        return decrypt_with_ad(inOut, authenticating: Data.init());
    }
}

struct SymmetricState {
    var cipherState: CipherState;
    var chainingKey: Data; // Salt
    var hashOutput: Data;

    static func initializeSymmetric(_ protocolName: Data) -> Self {
        let paddingNeeded = 32 - protocolName.count;
        let hashOutput: Data;
        if paddingNeeded >= 0 {
            hashOutput = protocolName + Data.init(count: paddingNeeded);
        } else {
            hashOutput = Data(SHA256.hash(data: protocolName));
        }
        let chainingKey = hashOutput;
        let cipherState = CipherState.init(fromKey: SymmetricKey.init(data: Data()));
        return Self.init(cipherState: cipherState, chainingKey: chainingKey, hashOutput: hashOutput);
    }

    mutating func mix_key(inputKeyMaterial: SymmetricKey) {
        let (chainingKey, tempK): (Data, Data) = hkdf(chainingKey: self.chainingKey, inputKeyData: inputKeyMaterial.withUnsafeBytes { Data($0) });
        self.chainingKey = chainingKey;
        assert(tempK.count == 32);
        cipherState.initializeKey(SymmetricKey.init(data: tempK));
    }

    mutating func mix_key(sharedSecret: SharedSecret) {
        let allKeys = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: chainingKey, sharedInfo: Data(), outputByteCount: 2 * 32)
        let (chainingKey, tempK): (Data, Data) = allKeys.withUnsafeBytes {
            assert($0.count == 32 * 2)
            return (Data.init($0[..<32]), Data.init($0[32 * 1..<32 * 2]));
        }
        self.chainingKey = chainingKey;
        assert(tempK.count == 32);
        cipherState.initializeKey(SymmetricKey.init(data: tempK));
    }

    mutating func mix_hash(data: Data) {
        var hasher = SHA256.init();
        hasher.update(data: self.hashOutput);
        hasher.update(data: data);
        hashOutput = Data.init(hasher.finalize());
    }

    mutating func mix_key_and_hash(inputKeyData: Data) {
        let (chainingKey, tempH, tempK): (Data, Data, Data) = hkdf(chainingKey: self.chainingKey, inputKeyData: inputKeyData);
        self.chainingKey = chainingKey;
        mix_hash(data: tempH);
        assert(tempK.count == 32);
        cipherState.initializeKey(SymmetricKey.init(data: tempK));
    }

    mutating func mix_key_and_hash(inputKeyMaterial: SymmetricKey) {
        let (chainingKey, tempH, tempK): (Data, Data, Data) = hkdf(chainingKey: self.chainingKey, inputKeyData: inputKeyMaterial.withUnsafeBytes { Data($0) });
        self.chainingKey = chainingKey;
        mix_hash(data: tempH);
        assert(tempK.count == 32);
        cipherState.initializeKey(SymmetricKey.init(data: tempK));
    }

    func getHandshakeHash() -> Data {
        return self.hashOutput;
    }

    mutating func encrypt_and_hash(inOut: Data) -> Data {
        let out: Data = cipherState.encrypt_with_ad(inOut, authenticating: hashOutput);
        mix_hash(data: out);
        return out;
    }

    mutating func decrypt_and_hash(inOut: Data) -> Data {
        let out = cipherState.decrypt_with_ad(inOut, authenticating: hashOutput);
        mix_hash(data: inOut);
        return out;
    }

    func split() -> (CipherState, CipherState) {
        let (tempK1, tempK2): (Data, Data) = hkdf(chainingKey: self.chainingKey, inputKeyData: Data.init());
        assert(tempK1.count == 32);
        assert(tempK2.count == 32);
        let c1 = CipherState.init(fromKey: SymmetricKey.init(data: tempK1));
        let c2 = CipherState.init(fromKey: SymmetricKey.init(data: tempK2));
        return (c1, c2);
    }
}

struct HandshakeState {
    static let DHLEN: UInt = 32;

    var symmetricState: SymmetricState;
    var localStaticKey: Curve25519.KeyAgreement.PrivateKey?;
    var localEphemeralKey: Curve25519.KeyAgreement.PrivateKey?;
    var remoteStaticKey: Curve25519.KeyAgreement.PublicKey?;
    var remoteEphemeralKey: Curve25519.KeyAgreement.PublicKey?;
    var preSharedKey: Data?;

    mutating func clear() {
        self.localStaticKey = nil;
        self.localEphemeralKey = nil;
        self.remoteEphemeralKey = nil;
        self.preSharedKey = nil;
    }

    static func initialize_initiator(_ prologue: Data,
                              localStaticKey: Curve25519.KeyAgreement.PrivateKey,
                              remoteStaticKey: Curve25519.KeyAgreement.PublicKey,
                              preSharedKey: Data) -> Self {
        var symmetricState = SymmetricState.initializeSymmetric("Noise_IKpsk2_25519_ChaChaPoly_SHA256".data(using: .ascii)!);
        symmetricState.mix_hash(data: prologue);
        symmetricState.mix_hash(data: remoteStaticKey.rawRepresentation);
        let localStaticKey = localStaticKey;
        let remoteStaticKey = remoteStaticKey;
        let preSharedKey = preSharedKey;
        return HandshakeState.init(symmetricState: symmetricState,
                                   localStaticKey: localStaticKey,
                                   localEphemeralKey: nil,
                                   remoteStaticKey: remoteStaticKey,
                                   remoteEphemeralKey: nil,
                                   preSharedKey: preSharedKey);
    }

    static func initialize_responder(_ prologue: Data,
                              localStaticKey: Curve25519.KeyAgreement.PrivateKey,
                              preSharedKey: Data) -> Self {
        var symmetricState = SymmetricState.initializeSymmetric("Noise_IKpsk2_25519_ChaChaPoly_SHA256".data(using: .ascii)!);
        symmetricState.mix_hash(data: prologue);
        symmetricState.mix_hash(data: localStaticKey.publicKey.rawRepresentation);
        let localStaticKey = localStaticKey;
        let preSharedKey = preSharedKey;
        return HandshakeState.init(symmetricState: symmetricState,
                                   localStaticKey: localStaticKey,
                                   localEphemeralKey: nil,
                                   remoteStaticKey: nil,
                                   remoteEphemeralKey: nil,
                                   preSharedKey: preSharedKey);
    }

    mutating func write_message_a(_ payload: Data) -> Data {
        var buffer: Data = Data.init();

        // e
        if (self.localEphemeralKey == nil) {
            self.localEphemeralKey = Curve25519.KeyAgreement.PrivateKey.init();
        }

        let localEphemeralPubkey = localEphemeralKey!.publicKey;
        buffer.append(localEphemeralPubkey.rawRepresentation);
        symmetricState.mix_hash(data: localEphemeralPubkey.rawRepresentation);
        symmetricState.mix_key(inputKeyMaterial: SymmetricKey.init(data: localEphemeralPubkey.rawRepresentation));

        // es
        let shared1 = try! self.localEphemeralKey!.sharedSecretFromKeyAgreement(with: self.remoteStaticKey!);
        symmetricState.mix_key(sharedSecret: shared1);

        // s
        let encryptedS = symmetricState.encrypt_and_hash(inOut: localStaticKey!.publicKey.rawRepresentation);
        buffer.append(encryptedS);

        // ss
        let shared2 = try! self.localStaticKey!.sharedSecretFromKeyAgreement(with: self.remoteStaticKey!);
        symmetricState.mix_key(sharedSecret: shared2);

        // End
        buffer.append(symmetricState.encrypt_and_hash(inOut: payload));
        return buffer;
    }

    mutating func read_message_a(_ message: Data) -> Data {
        var currentIndex: Data.Index = 0;

        // e
        assert(self.remoteEphemeralKey == nil);
        self.remoteEphemeralKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: message[currentIndex..<currentIndex+Int(Self.DHLEN)])
        currentIndex += Int(Self.DHLEN);
        self.symmetricState.mix_hash(data: self.remoteEphemeralKey!.rawRepresentation);
        symmetricState.mix_key(inputKeyMaterial: SymmetricKey.init(data: remoteEphemeralKey!.rawRepresentation));

        // es
        assert(self.localStaticKey != nil);
        let shared1 = try! self.localStaticKey!.sharedSecretFromKeyAgreement(with: self.remoteEphemeralKey!);
        symmetricState.mix_key(sharedSecret: shared1);

        // s
        let temp: Data;
        if symmetricState.cipherState.hasKey() {
            temp = Data.init(message[currentIndex..<currentIndex + Int(Self.DHLEN)+16+12]) //modded
            currentIndex += Int(Self.DHLEN+16+12);
        } else {
            temp = Data.init(message[currentIndex..<currentIndex + Int(Self.DHLEN)])
            currentIndex += Int(Self.DHLEN);
        }
        assert(self.remoteStaticKey == nil);
        self.remoteStaticKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: symmetricState.decrypt_and_hash(inOut: temp));

        // ss
        let shared2 = try! self.localStaticKey!.sharedSecretFromKeyAgreement(with: self.remoteStaticKey!);
        symmetricState.mix_key(sharedSecret: shared2);

        // End
        return symmetricState.decrypt_and_hash(inOut: message[currentIndex...]);
    }

    mutating func write_message_b(_ payload: Data) -> (Data, CipherState, CipherState) {
        var buffer: Data = Data.init();

        // e
        if self.localEphemeralKey == nil {
            self.localEphemeralKey = Curve25519.KeyAgreement.PrivateKey.init();
        }

        buffer.append(localEphemeralKey!.publicKey.rawRepresentation);
        symmetricState.mix_hash(data: localEphemeralKey!.publicKey.rawRepresentation);
        symmetricState.mix_key(inputKeyMaterial: SymmetricKey.init(data: localEphemeralKey!.publicKey.rawRepresentation));

        // ee
        let shared1 = try! self.localEphemeralKey!.sharedSecretFromKeyAgreement(with: self.remoteEphemeralKey!);
        symmetricState.mix_key(sharedSecret: shared1);

        // se
        let shared2 = try! self.localEphemeralKey!.sharedSecretFromKeyAgreement(with: self.remoteStaticKey!);
        symmetricState.mix_key(sharedSecret: shared2);

        // psk
        symmetricState.mix_key_and_hash(inputKeyData: self.preSharedKey!);

        // End
        buffer.append(symmetricState.encrypt_and_hash(inOut: payload));
        let (rv1, rv2) = symmetricState.split();
        return (buffer, rv1, rv2)
    }

    mutating func read_message_b(_ message: Data) -> (Data, CipherState, CipherState) {
        var currentIndex: Data.Index = 0;

        // e
        assert(self.remoteEphemeralKey == nil);
        if self.remoteEphemeralKey == nil {
            self.remoteEphemeralKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: message[currentIndex..<currentIndex+Int(Self.DHLEN)])
            currentIndex += Int(Self.DHLEN);
        }
        self.symmetricState.mix_hash(data: self.remoteEphemeralKey!.rawRepresentation);
        symmetricState.mix_key(inputKeyMaterial: SymmetricKey.init(data: remoteEphemeralKey!.rawRepresentation));

        // ee
        let shared1 = try! self.localEphemeralKey!.sharedSecretFromKeyAgreement(with: self.remoteEphemeralKey!);
        symmetricState.mix_key(sharedSecret: shared1);

        // se
        let shared2 = try! self.localStaticKey!.sharedSecretFromKeyAgreement(with: self.remoteEphemeralKey!);
        symmetricState.mix_key(sharedSecret: shared2);

        // psk
        symmetricState.mix_key_and_hash(inputKeyData: self.preSharedKey!);

        // End
        let payload = symmetricState.decrypt_and_hash(inOut: message[currentIndex...]);
        let (rv1, rv2) = symmetricState.split();
        return (payload, rv1, rv2);
    }
}
