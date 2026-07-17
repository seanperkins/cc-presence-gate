import Foundation
import CCFidoCore

let args = Array(CommandLine.arguments.dropFirst())
func usage() -> Never {
    FileHandle.standardError.write(Data("usage: cc-fido {daemon|hook|write <path>|enroll|install|enroll-file <path> [mode]|enroll-dir <path>}\n".utf8))
    exit(2)
}
guard let cmd = args.first else { usage() }
switch cmd {
case "daemon":
    try Broker().serve()
case "write":
    guard args.count >= 2 else { usage() }
    exit(runWrite(path: args[1], content: FileHandle.standardInput.readDataToEndOfFile()))
default:
    FileHandle.standardError.write(Data("cc-fido: unknown command \(cmd)\n".utf8)); exit(2)
}
