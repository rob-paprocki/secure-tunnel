// Per-app split tunnelling for macOS: a transparent proxy that sees every new
// connection with the app it came from. Connections that should use the VPN
// are left alone (the routing table sends them into the tunnel); the rest are
// relayed out through a physical interface (Wi-Fi or Ethernet), bypassing it.

import Foundation
import Network
import NetworkExtension
import Security

final class TransparentProxy: NETransparentProxyProvider {
    /// "only": just the listed apps use the tunnel. "except": the listed apps skip it.
    private var mode = "except"
    private var rules: [String] = []
    private let queue = DispatchQueue(label: "securetunnel.proxy")

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        if let conf = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration {
            mode = conf["mode"] as? String ?? "except"
            rules = (conf["apps"] as? [String] ?? []).map { Self.norm($0) }.filter { !$0.isEmpty }
        }
        NSLog("SecureTunnel proxy: mode=%@ apps=%@", mode, rules.joined(separator: ","))
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil, localPrefix: 0, protocol: .TCP, direction: .outbound),
            NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil, localPrefix: 0, protocol: .UDP, direction: .outbound),
        ]
        setTunnelNetworkSettings(settings) { error in completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    // MARK: matching (same rules as the Linux and Windows builds)

    static func norm(_ s: String) -> String {
        var v = s.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "\\", with: "/").lowercased()
        for suffix in [".exe", ".app"] where v.hasSuffix(suffix) {
            v.removeLast(suffix.count)
        }
        return v
    }

    private func appPath(_ meta: NEFlowMetaData) -> String {
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: meta.sourceAppAuditToken ?? Data()] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return "" }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return "" }
        var url: CFURL?
        guard SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let url else { return "" }
        return (url as URL).path
    }

    private func listed(_ meta: NEFlowMetaData) -> Bool {
        let path = Self.norm(appPath(meta))
        let ident = meta.sourceAppSigningIdentifier.lowercased()
        let base = path.split(separator: "/").last.map(String.init) ?? ""
        for r in rules {
            if r.contains("/") {
                let dir = r.hasSuffix("/") ? String(r.dropLast()) : r
                if path == dir || path.hasPrefix(dir + "/") { return true }
            } else if base == r || ident == r || ident.hasSuffix("." + r) {
                return true
            }
        }
        return false
    }

    // MARK: flows

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let isListed = listed(flow.metaData)
        let tunneled = mode == "only" ? isListed : !isListed
        if tunneled {
            return false // let the system route it: the VPN's routes send it into the tunnel
        }
        if let tcp = flow as? NEAppProxyTCPFlow {
            relayTCP(tcp)
            return true
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            relayUDP(udp)
            return true
        }
        return false
    }

    /// Connection parameters that keep traffic off the tunnel's utun interface.
    private func direct(_ base: NWParameters) -> NWParameters {
        base.prohibitedInterfaceTypes = [.other]
        return base
    }

    private func relayTCP(_ flow: NEAppProxyTCPFlow) {
        let remote = flow.remoteFlowEndpoint
        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            guard let self, error == nil else {
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                return
            }
            let conn = NWConnection(to: remote, using: self.direct(.tcp))
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.pumpOut(flow, conn)
                    self.pumpIn(flow, conn)
                case .failed, .cancelled:
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                default:
                    break
                }
            }
            conn.start(queue: self.queue)
        }
    }

    private func pumpOut(_ flow: NEAppProxyTCPFlow, _ conn: NWConnection) {
        flow.readData { data, error in
            if let data, !data.isEmpty, error == nil {
                conn.send(content: data, completion: .contentProcessed { e in
                    if e == nil { self.pumpOut(flow, conn) } else { conn.cancel() }
                })
            } else {
                conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
            }
        }
    }

    private func pumpIn(_ flow: NEAppProxyTCPFlow, _ conn: NWConnection) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { data, _, done, error in
            if let data, !data.isEmpty {
                flow.write(data) { e in
                    if e != nil { conn.cancel(); return }
                    if !done && error == nil { self.pumpIn(flow, conn) }
                }
            }
            if done || error != nil {
                flow.closeWriteWithError(nil)
                if data == nil || data!.isEmpty { conn.cancel() }
            }
        }
    }

    private func relayUDP(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalFlowEndpoint: nil) { [weak self] error in
            guard let self, error == nil else {
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                return
            }
            var conns: [String: NWConnection] = [:]
            func read() {
                flow.readDatagrams { pairs, error in
                    guard let pairs, error == nil, !pairs.isEmpty else {
                        conns.values.forEach { $0.cancel() }
                        flow.closeWriteWithError(nil)
                        return
                    }
                    for (data, endpoint) in pairs {
                        let key = "\(endpoint)"
                        let conn: NWConnection
                        if let c = conns[key] {
                            conn = c
                        } else {
                            conn = NWConnection(to: endpoint, using: self.direct(.udp))
                            conns[key] = conn
                            conn.start(queue: self.queue)
                            func receive() {
                                conn.receiveMessage { reply, _, _, e in
                                    if let reply, !reply.isEmpty {
                                        flow.writeDatagrams([(reply, endpoint)]) { _ in }
                                    }
                                    if e == nil { receive() }
                                }
                            }
                            receive()
                        }
                        conn.send(content: data, completion: .contentProcessed { _ in })
                    }
                    read()
                }
            }
            read()
        }
    }
}
