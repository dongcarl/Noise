//
//  Hash.swift
//  Noise
//
//  Created by Carl Dong on 2/28/21.
//

import CryptoKit
import Foundation

fileprivate func internalHKDF(chainingKey: Data, inputKeyData: Data) -> (Data, Data, Data) {
    let tempKey: Data = Data(HMAC<SHA256>.authenticationCode(for: inputKeyData, using: SymmetricKey.init(data: chainingKey)));
    let output1: Data = Data(HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: SymmetricKey.init(data: tempKey)));
    let output2: Data = Data(HMAC<SHA256>.authenticationCode(for: output1 + Data([0x02]), using: SymmetricKey.init(data: tempKey)));
    return (tempKey, output1, output2);
}

fileprivate func internalHKDF(chainingKey: Data, inputKeyData: Data) -> (Data, Data, Data, Data) {
    let (tempKey, output1, output2) = internalHKDF(chainingKey: chainingKey, inputKeyData: inputKeyData);
    let output3: Data = Data(HMAC<SHA256>.authenticationCode(for: output2 + Data([0x03]), using: SymmetricKey.init(data: tempKey)));
    return (tempKey, output1, output2, output3);
}

func hkdf(chainingKey: Data, inputKeyData: Data) -> (Data, Data) {
    if #available(OSX 11.0, *) {
        let allOut = hkdfApple(chainingKey: chainingKey, inputKeyData: inputKeyData, numChunks: 2);
        assert(allOut.count == 2);
        return (allOut[0], allOut[1]);
    } else {
        let (_, output1, output2) = internalHKDF(chainingKey: chainingKey, inputKeyData: inputKeyData);
        return (output1, output2);
    }
}

func hkdf(chainingKey: Data, inputKeyData: Data) -> (Data, Data, Data) {
    if #available(OSX 11.0, *) {
        let allOut = hkdfApple(chainingKey: chainingKey, inputKeyData: inputKeyData, numChunks: 3);
        assert(allOut.count == 3);
        return (allOut[0], allOut[1], allOut[2]);
    } else {
        let (_, output1, output2, output3) = internalHKDF(chainingKey: chainingKey, inputKeyData: inputKeyData);
        return (output1, output2, output3);
    }
}

@available(OSX 11.0, *)
fileprivate func hkdfApple(chainingKey: Data, inputKeyData: Data, numChunks: UInt) -> [Data] {
    let allKeys = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey.init(data: inputKeyData), salt: chainingKey, outputByteCount: Int(numChunks) * 32);
    return allKeys.withUnsafeBytes {
        var rv: [Data] = [Data].init();
        for i in 0..<Int(numChunks) {
            let candidate = Data.init($0[i * 32..<(i + 1) * 32]);
            assert(candidate.count == 32);
            rv.append(candidate);
        }
        return rv;
    }
}
