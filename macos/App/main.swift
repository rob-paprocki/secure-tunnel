// Secure Tunnel.app main program. Started normally, it hands over to the
// window (the Rust program `secure-tunnel-ui` next to it). Started with
// `--netext <command>`, it manages the per-app split-tunnelling extension:
//   --netext install                 ask macOS to install/approve the extension
//   --netext enable <only|except> <apps, one per line>
//   --netext disable
//   --netext status

import AppKit
import Foundation
import NetworkExtension
import SystemExtensions

let extensionID = (Bundle.main.bundleIdentifier ?? "com.example.securetunnel") + ".proxy"
let args = CommandLine.arguments

func finish(_ code: Int32, _ message: String) -> Never {
    FileHandle.standardOutput.write((message + "\n").data(using: .utf8)!)
    exit(code)
}

guard let i = args.firstIndex(of: "--netext") else {
    // Normal start: replace this process with the window program.
    let ui = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/secure-tunnel-ui").path
    var cargs: [UnsafeMutablePointer<CChar>?] = [strdup(ui)]
    for a in args.dropFirst() { cargs.append(strdup(a)) }
    cargs.append(nil)
    execv(ui, cargs)
    finish(1, "Could not start \(ui)")
}

let command = args.count > i + 1 ? args[i + 1] : "status"

final class Installer: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("approval-needed: allow Secure Tunnel in System Settings > General > Login Items & Extensions > Network Extensions")
        // Take the person straight to the switch they need to turn on.
        if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
            NSWorkspace.shared.open(url)
        }
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        finish(0, result == .completed ? "installed" : "installed-after-restart")
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        finish(2, "install-failed: \(error.localizedDescription)")
    }
}

func withManager(_ body: @escaping (NETransparentProxyManager) -> Void) {
    NETransparentProxyManager.loadAllFromPreferences { managers, error in
        if let error { finish(3, "load-failed: \(error.localizedDescription)") }
        body(managers?.first ?? NETransparentProxyManager())
    }
}

let installer = Installer()
switch command {
case "install":
    let req = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
    req.delegate = installer
    OSSystemExtensionManager.shared.submitRequest(req)
case "enable":
    let mode = args.count > i + 2 ? args[i + 2] : "except"
    let apps = args.count > i + 3 ? args[i + 3].split(separator: "\n").map(String.init) : []
    withManager { m in
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extensionID
        proto.serverAddress = "Secure Tunnel"
        proto.providerConfiguration = ["mode": mode, "apps": apps]
        m.protocolConfiguration = proto
        m.localizedDescription = "Secure Tunnel per-app routing"
        m.isEnabled = true
        m.saveToPreferences { error in
            if let error { finish(4, "save-failed: \(error.localizedDescription)") }
            m.loadFromPreferences { _ in
                (m.connection as? NETunnelProviderSession)?.stopTunnel()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    do {
                        try (m.connection as? NETunnelProviderSession)?.startTunnel(options: nil)
                        finish(0, "enabled")
                    } catch {
                        finish(5, "start-failed: \(error.localizedDescription)")
                    }
                }
            }
        }
    }
case "disable":
    withManager { m in
        (m.connection as? NETunnelProviderSession)?.stopTunnel()
        finish(0, "disabled")
    }
default:
    withManager { m in
        finish(0, "status: \(m.connection.status.rawValue)")
    }
}
RunLoop.main.run(until: Date().addingTimeInterval(120))
finish(6, "timed-out")
