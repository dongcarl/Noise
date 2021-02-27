//
//  NoiseSession.swift
//  Noise
//
//  Created by Carl Dong on 2/27/21.
//

import CryptoKit
import Foundation

struct NoiseSession {
    var handshakeState: HandshakeState;
    var handshakeHash: Data;
    var localCipherState: CipherState?;
    var remoteCipherState: CipherState?;
    var messageCount: UInt = 0;
    var isInitiator: Bool;
    var isTransport: Bool;

    mutating public func setEphemeralKey(key: Curve25519.KeyAgreement.PrivateKey) {
        handshakeState.localEphemeralKey = key;
    }

    public static func init_initiator(prologue: Data,
                               localStaticKey: Curve25519.KeyAgreement.PrivateKey,
                               remoteStaticKey: Curve25519.KeyAgreement.PublicKey?,
                               preSharedKey: Data) -> Self {
        return NoiseSession.init(
            handshakeState: HandshakeState.initialize_initiator(prologue,
                                                                localStaticKey: localStaticKey,
                                                                remoteStaticKey: remoteStaticKey!,
                                                                preSharedKey: preSharedKey),
            handshakeHash: Data.init(count: 32),
            localCipherState: nil,
            remoteCipherState: nil,
            messageCount: 0,
            isInitiator: true,
            isTransport: false);
    }

    public static func init_responder(prologue: Data,
                               localStaticKey: Curve25519.KeyAgreement.PrivateKey,
                               preSharedKey: Data) -> Self {
        return NoiseSession.init(
            handshakeState: HandshakeState.initialize_responder(prologue,
                                                                localStaticKey: localStaticKey,
                                                                preSharedKey: preSharedKey),
            handshakeHash: Data.init(count: 32),
            localCipherState: nil,
            remoteCipherState: nil,
            messageCount: 0,
            isInitiator: false,
            isTransport: false);
    }

    mutating func sendMessage(input: Data) -> Data {
        let rv: Data;
        if self.messageCount == 0 {
            rv = self.handshakeState.write_message_a(input);
        } else if (self.messageCount == 1) {
            let temp = self.handshakeState.write_message_b(input);
            self.handshakeHash = temp.0;
            self.isTransport = true;
            self.localCipherState = temp.1;
            self.remoteCipherState = temp.2;
            self.handshakeState.clear();
            rv = temp.0;
        } else if self.isInitiator {
            rv = self.localCipherState!.write_message_regular(inOut: input);
        } else {
            rv = self.remoteCipherState!.write_message_regular(inOut: input);
        }
        self.messageCount += 1;
        return rv;
    }

    mutating func recvMessage(input: Data) -> Data {
        let rv: Data;
        if self.messageCount == 0 {
            rv = self.handshakeState.read_message_a(input);
        } else if (self.messageCount == 1) {
            let temp = self.handshakeState.read_message_b(input);
            self.handshakeHash = temp.0;
            self.isTransport = true;
            self.localCipherState = temp.1;
            self.remoteCipherState = temp.2;
            self.handshakeState.clear();
            rv = temp.0;
        } else if self.isInitiator {
            rv = self.remoteCipherState!.read_message_regular(inOut: input);
        } else {
            rv = self.localCipherState!.read_message_regular(inOut: input);
        }
        self.messageCount += 1;
        return rv;
    }
}
