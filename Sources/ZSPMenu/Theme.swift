import AppKit
import SwiftUI

/// Colours, cards, pills and the tab bar every screen shares.
enum Theme {
    static let accent = Color(light: "#ea580c", dark: "#fb923c")

    static let safe = Color(light: "#16a34a", dark: "#22c55e")
    static let warn = Color(light: "#d97706", dark: "#fbbf24")
    static let danger = Color(light: "#dc2626", dark: "#f87171")
    static let info = Color(light: "#2563eb", dark: "#60a5fa")
    static let violet = Color(light: "#7c3aed", dark: "#a78bfa")
    static let teal = Color(light: "#0d9488", dark: "#2dd4bf")
    static let slate = Color(light: "#64748b", dark: "#94a3b8")

    static let protectedGradient = LinearGradient(
        colors: [Color(light: "#0f766e", dark: "#115e59"), Color(light: "#4f46e5", dark: "#3730a3")],
        startPoint: .topLeading, endPoint: .bottomTrailing)
    static let exposedGradient = LinearGradient(
        colors: [Color(light: "#dc2626", dark: "#991b1b"), Color(light: "#ea580c", dark: "#9a3412")],
        startPoint: .topLeading, endPoint: .bottomTrailing)

    static let cardFill = Color(light: "#ffffff", dark: "#25252a").opacity(0.8)
    static let cardStroke = Color.primary.opacity(0.07)
}

extension Color {
    init(hex: String) {
        let v = UInt64(hex.dropFirst(), radix: 16) ?? 0
        self.init(.sRGB, red: Double((v >> 16) & 0xff) / 255, green: Double((v >> 8) & 0xff) / 255,
                  blue: Double(v & 0xff) / 255, opacity: 1)
    }

    /// A colour with its own light and dark step, not an automatic flip.
    init(light: String, dark: String) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            return NSColor(Color(hex: isDark ? dark : light))
        })
    }
}

/// A rounded panel with an optional title row.
struct Card<Content: View>: View {
    var title: String?
    var symbol: String?
    var tint: Color = Theme.accent
    var trailing: AnyView?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let title {
                HStack(spacing: 6) {
                    if let symbol { Image(systemName: symbol).font(.callout.weight(.bold)).foregroundStyle(tint) }
                    Text(title).font(.headline)
                    Spacer()
                    trailing
                }
            }
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(Theme.cardFill))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Theme.cardStroke))
    }
}

/// A small coloured capsule label.
struct Pill: View {
    let text: String
    var symbol: String?
    var color: Color

    var body: some View {
        HStack(spacing: 4) {
            if let symbol { Image(systemName: symbol) }
            Text(text)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(color)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(Capsule().fill(color.opacity(0.14)))
    }
}

/// A coloured square with a white symbol.
struct SymbolTile: View {
    let symbol: String
    let color: Color
    var size: CGFloat = 30

    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
            .fill(LinearGradient(colors: [color, color.opacity(0.75)], startPoint: .top, endPoint: .bottom))
            .frame(width: size, height: size)
            .overlay(Image(systemName: symbol).font(.system(size: size * 0.48, weight: .semibold)).foregroundStyle(.white))
    }
}

/// A tinted capsule button: the panel's buttons, from "Check in AWS" to Quit.
struct PillButtonStyle: ButtonStyle {
    var color: Color
    var filled = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .foregroundStyle(filled ? Color.white : color)
            .padding(.horizontal, 12).padding(.vertical, 6)
            .background(Capsule().fill(filled ? AnyShapeStyle(color) : AnyShapeStyle(color.opacity(configuration.isPressed ? 0.24 : 0.12))))
            .opacity(configuration.isPressed ? 0.85 : 1)
            .contentShape(Capsule())
    }
}

extension ButtonStyle where Self == PillButtonStyle {
    static func pill(_ color: Color, filled: Bool = false) -> PillButtonStyle { PillButtonStyle(color: color, filled: filled) }
}

enum Tab: Int, CaseIterable, Identifiable {
    case overview, keys, protection, audit
    var id: Int { rawValue }

    var title: String {
        switch self {
        case .overview: return "Overview"
        case .keys: return "Keys"
        case .protection: return "MFA & phone"
        case .audit: return "Audit trail"
        }
    }

    var symbol: String {
        switch self {
        case .overview: return "shield.lefthalf.filled"
        case .keys: return "key.fill"
        case .protection: return "lock.iphone"
        case .audit: return "list.bullet.clipboard.fill"
        }
    }

    var color: Color {
        switch self {
        case .overview: return Color(light: "#4f46e5", dark: "#818cf8")
        case .keys: return Color(light: "#ea580c", dark: "#fb923c")
        case .protection: return Color(light: "#9333ea", dark: "#c084fc")
        case .audit: return Color(light: "#0d9488", dark: "#2dd4bf")
        }
    }
}

/// Icon-over-label tabs, each with its own colour; the selected one fills.
struct TabBar: View {
    @Binding var selection: Tab
    var badges: [Tab: Int] = [:]
    @State private var hover: Tab?

    var body: some View {
        HStack(spacing: 6) {
            ForEach(Tab.allCases) { tab in
                let on = tab == selection
                Button { selection = tab } label: {
                    VStack(spacing: 3) {
                        Image(systemName: tab.symbol).font(.system(size: 15, weight: .semibold))
                        Text(tab.title).font(.caption.weight(on ? .semibold : .medium))
                    }
                    .foregroundStyle(on ? Color.white : tab.color)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(on ? AnyShapeStyle(LinearGradient(colors: [tab.color, tab.color.opacity(0.8)], startPoint: .top, endPoint: .bottom))
                                     : AnyShapeStyle(tab.color.opacity(hover == tab ? 0.14 : 0.07))))
                    .overlay(alignment: .topTrailing) {
                        if let n = badges[tab], n > 0 {
                            Text("\(n)").font(.system(size: 9, weight: .bold)).foregroundStyle(.white)
                                .padding(.horizontal, 5).padding(.vertical, 1)
                                .background(Capsule().fill(Theme.danger))
                                .offset(x: -6, y: 4)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .onHover { hover = $0 ? tab : (hover == tab ? nil : hover) }
            }
        }
    }
}
