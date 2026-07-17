import Foundation

public enum CanonicalError: Error { case notEncodable }

public struct SignedDocument: Codable, Equatable {
    public let v: Int
    public let op: String
    public let path: String
    public let contentSha256: String
    public let cwd: String
    public let nonce: String
    public let callerUid: Int
    public let contentMode: String
    enum CodingKeys: String, CodingKey {
        case v, op, path, cwd, nonce
        case contentSha256 = "content_sha256"
        case callerUid = "caller_uid"
        case contentMode = "content_mode"
    }
}
public func buildSignedDocument(op: String, path: String, contentSha256: String, cwd: String,
                                nonceHex: String, callerUid: Int,
                                contentMode: String = "inline") -> SignedDocument {
    SignedDocument(v: 1, op: op, path: path, contentSha256: contentSha256, cwd: cwd,
                   nonce: nonceHex, callerUid: callerUid, contentMode: contentMode)
}
public func canonicalBytes<T: Encodable>(_ obj: T) throws -> Data {
    let enc = JSONEncoder()
    enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try enc.encode(obj)
}
/// Canonical bytes for an arbitrary already-parsed JSON object (the `approve` payload).
/// .sortedKeys sorts nested keys too; compact by default.
public func canonicalJSON(_ obj: [String: Any]) throws -> Data {
    guard JSONSerialization.isValidJSONObject(obj) else { throw CanonicalError.notEncodable }
    return try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes])
}
