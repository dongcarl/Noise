//
//  NoiseTests.swift
//  NoiseTests
//
//  Created by Carl Dong on 2/27/21.
//

import CryptoKit
import XCTest
@testable import Noise

extension String {
    enum ExtendedEncoding {
        case hexadecimal
    }

    func data(using encoding:ExtendedEncoding) -> Data? {
        let hexStr = self.dropFirst(self.hasPrefix("0x") ? 2 : 0)

        guard hexStr.count % 2 == 0 else { return nil }

        var newData = Data(capacity: hexStr.count/2)

        var indexIsEven = true
        for i in hexStr.indices {
            if indexIsEven {
                let byteRange = i...hexStr.index(after: i)
                guard let byte = UInt8(hexStr[byteRange], radix: 16) else { return nil }
                newData.append(byte)
            }
            indexIsEven.toggle()
        }
        return newData
    }
}

class NoiseTests: XCTestCase {
    static let prologue: Data = "4a6f686e2047616c74".data(using: .hexadecimal)!;

    var initiator: NoiseSession?;
    var responder: NoiseSession?;

    static func randomPreshared() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32);
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes);
        assert(status == errSecSuccess);
        return Data.init(bytes);
    }

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        let initiatorKey = try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1".data(using: .hexadecimal)!);
        let responderKey = try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893".data(using: .hexadecimal)!);
        let preSharedKey = "54686973206973206d7920417573747269616e20706572737065637469766521".data(using: .hexadecimal)!;


        initiator = NoiseSession.init_initiator(prologue: Self.prologue,
                                                localStaticKey: initiatorKey,
                                                remoteStaticKey: responderKey.publicKey,
                                                preSharedKey: preSharedKey);
        responder = NoiseSession.init_responder(prologue: Self.prologue,
                                                localStaticKey: responderKey,
                                                preSharedKey: preSharedKey);

        let initiatorEphemeralKey = try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a".data(using: .hexadecimal)!);
        initiator!.setEphemeralKey(key: initiatorEphemeralKey);

        let responderEphemeralKey = try Curve25519.KeyAgreement.PrivateKey.init(rawRepresentation: "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b".data(using: .hexadecimal)!);
        responder!.setEphemeralKey(key: responderEphemeralKey);
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

//    @available(OSX 11.0, *)
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        var initiator = self.initiator!;
        var responder = self.responder!;

        assert(initiator.isTransport == false);
        assert(responder.isTransport == false);

        let messageAPlain: Data = "4c756477696720766f6e204d69736573".data(using: .hexadecimal)!;
        let messageA = initiator.sendMessage(input: messageAPlain);
        assert(messageAPlain == responder.recvMessage(input: messageA));

        assert(initiator.isTransport == false);
        assert(responder.isTransport == false);

        let messageBPlain: Data = "4d757272617920526f746862617264".data(using: .hexadecimal)!;
        let messageB = responder.sendMessage(input: messageBPlain);
        assert(messageBPlain == initiator.recvMessage(input: messageB));

        assert(initiator.isTransport == true);
        assert(responder.isTransport == true);

        let messageCPlain: Data = "462e20412e20486179656b".data(using: .hexadecimal)!;
        let messageC = initiator.sendMessage(input: messageCPlain);
        assert(messageCPlain == responder.recvMessage(input: messageC));

        let messageDPlain: Data = "4361726c204d656e676572".data(using: .hexadecimal)!;
        let messageD = responder.sendMessage(input: messageDPlain);
        assert(messageDPlain == initiator.recvMessage(input: messageD));

        let messageEPlain: Data = "4a65616e2d426170746973746520536179".data(using: .hexadecimal)!;
        let messageE = initiator.sendMessage(input: messageEPlain);
        assert(messageEPlain == responder.recvMessage(input: messageE));

        let messageFPlain: Data = "457567656e2042f6686d20766f6e2042617765726b".data(using: .hexadecimal)!;
        let messageF = responder.sendMessage(input: messageFPlain);
        assert(messageFPlain == initiator.recvMessage(input: messageF));

        assert(initiator.isTransport == true);
        assert(responder.isTransport == true);
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

}
