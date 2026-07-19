import Foundation
/// Abstract, transport-agnostic cancellation handle for an in-flight signing ceremony.
/// FIDO supplies a Process-terminating impl; Secure Enclave will supply an LAContext-invalidating one.
public protocol CeremonyCanceller { func cancel() }
