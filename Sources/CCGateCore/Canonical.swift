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

public let INLINE_MAX = 4096

func escapeConfusables(_ s: String) -> String {
    var out = ""
    for scalar in s.unicodeScalars {
        let v = scalar.value
        let cat = scalar.properties.generalCategory
        let dangerous = v < 0x20 || v == 0x7f || v > 0x7e
            || cat == .format || cat == .lineSeparator || cat == .paragraphSeparator
            || (0x200b...0x200f).contains(v) || (0x202a...0x202e).contains(v)
        // Escape '<' too so the escape token "<U+XXXX>" cannot collide with literal input. (injectivity)
        if dangerous || v == 0x3c { out += String(format: "<U+%04X>", v) }
        else { out += String(scalar) }
    }
    return out
}
public func humanRendering(_ doc: SignedDocument, content: Data) -> String {
    let path = escapeConfusables(doc.path)
    let header = "\(doc.op.uppercased()) \(path)\ncwd: \(escapeConfusables(doc.cwd))"
    let tail = "\n\(content.count) bytes  sha256:\(doc.contentSha256)"   // FULL digest
    if content.count > INLINE_MAX { return "\(header)\n[digest mode — content not shown]\(tail)" }
    let body = String(data: content, encoding: .utf8).map(escapeConfusables) ?? "[binary, \(content.count) bytes]"
    return "\(header)\n---\n\(body)\n---\(tail)"
}
