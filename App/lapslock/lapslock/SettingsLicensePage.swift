import SwiftUI
import LicensingKit

/// The organization license: its state, and Activate, Refresh and Remove. Read when the page
/// opens, so the first page of Settings asks the license store for nothing.
struct SettingsLicensePage: View {
    let entitlement: EntitlementManager?
    let isDemo: Bool
    let tenantId: String?
    /// Domain of the signed-in account, shown on the Activate button so nobody licenses an
    /// organization they did not mean to.
    var signedInDomain: String? = nil
    /// Lets the root recompute `isPro` after Activate, Refresh or Remove.
    var entitlementDidChange: (() -> Void)? = nil

    @State private var license: EntitlementState = .free
    @State private var isLicenseActivated = false
    @State private var licenseIsForAnotherOrganization = false
    @State private var isFetchingLicense = false
    @State private var licenseMessage: String?

    var body: some View {
        Form {
            licenseSection
        }
        .navigationTitle("Organization License")
        .task { refreshLicense() }
    }

    // MARK: - organization license

    /// Contract section 7.1: the app contacts Kainor's server only after the user taps
    /// Activate here (or Refresh, later, or on the monthly schedule once activated). This
    /// section is the whole user-facing surface of that decision, so the footer says it out
    /// loud: until you activate, the app talks to Microsoft and nothing else.
    ///
    /// No pitch, no price. The same rule as the reveals section, this is a status readout
    /// and an action, for an audience that resents being sold to inside a settings screen.
    @ViewBuilder
    private var licenseSection: some View {
        if let entitlement, !isDemo {
            Section {
                if isLicenseActivated, licenseIsForAnotherOrganization {
                    // Activated, but for a different tenant. Not unlicensed, so do not
                    // show a bare Activate button as if nothing had happened, but the
                    // license does not apply here, so Refresh would fetch for the wrong
                    // organization. Say which situation this is and offer the way out.
                    LabeledContent("Plan", value: "Free here")
                    Button {
                        guard let tenantId else { return }
                        Task { await runLicenseAction { await entitlement.activate(tenantId: tenantId) } }
                    } label: {
                        Label(Self.activateLabel(signedInDomain), systemImage: "checkmark.seal")
                    }
                    .disabled(isFetchingLicense || tenantId == nil)
                    Button(role: .destructive) {
                        entitlement.remove()
                        licenseMessage = nil
                        refreshLicense()
                        entitlementDidChange?()
                    } label: {
                        Label("Remove license", systemImage: "xmark.circle")
                    }
                    .disabled(isFetchingLicense)
                } else if isLicenseActivated {
                    LabeledContent("Plan", value: Self.tierName(license.tier))
                    if let expires = license.expiresAt {
                        LabeledContent(
                            license.isInGrace ? "Could not refresh" : "Renews by",
                            value: SettingsView.relative(expires)
                        )
                    }
                    Button {
                        Task { await runLicenseAction { await entitlement.refreshNow() } }
                    } label: {
                        Label("Refresh license", systemImage: "arrow.clockwise")
                    }
                    .disabled(isFetchingLicense)
                    Button(role: .destructive) {
                        entitlement.remove()
                        licenseMessage = nil
                        refreshLicense()
                        entitlementDidChange?()
                    } label: {
                        Label("Remove license", systemImage: "xmark.circle")
                    }
                    .disabled(isFetchingLicense)
                } else {
                    Button {
                        guard let tenantId else { return }
                        Task { await runLicenseAction { await entitlement.activate(tenantId: tenantId) } }
                    } label: {
                        Label(Self.activateLabel(signedInDomain), systemImage: "checkmark.seal")
                    }
                    .disabled(isFetchingLicense || tenantId == nil)
                }
                if let licenseMessage {
                    Text(licenseMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } footer: {
                Text(licenseIsForAnotherOrganization
                    ? """
                      This license belongs to a different Microsoft organization, so it does \
                      not apply while you are signed in here. Activating replaces it; an \
                      install holds one license at a time.

                      If you manage several organizations, activate against your own \
                      instead. An MSP license covers you in every tenant you sign into, \
                      with nothing to re-activate.
                      """
                    : isLicenseActivated
                    ? """
                      Your license is keyed to this Microsoft tenant and checked against \
                      Kainor about once a month. Nothing about which devices or credentials \
                      you look at is ever sent.
                      """
                    : """
                      An organization license is keyed to your Microsoft tenant. Until you \
                      activate one, TenantKeep never contacts Kainor: it talks to Microsoft and \
                      nothing else, which you can confirm with a network proxy.

                      If you manage several organizations, activate while signed in to your \
                      own. An MSP license then covers every tenant you sign into.
                      """)
            }
        }
    }

    /// Names the organization being licensed. Falls back to generic wording rather than
    /// showing a GUID, which would mean nothing to the person reading it.
    static func activateLabel(_ domain: String?) -> String {
        guard let domain else { return "Activate organization license" }
        return "Activate license for \(domain)"
    }

    private func refreshLicense() {
        guard let entitlement else { return }
        isLicenseActivated = entitlement.isActivated
        license = entitlement.state(signedInTenantId: tenantId)
        licenseIsForAnotherOrganization = entitlement.isBoundToAnotherTenant(signedInTenantId: tenantId)
    }

    private func runLicenseAction(_ action: () async -> EntitlementFetchOutcome?) async {
        isFetchingLicense = true
        defer { isFetchingLicense = false }
        let outcome = await action()
        licenseMessage = Self.describe(outcome)
        refreshLicense()
        entitlementDidChange?()
    }

    static func tierName(_ tier: EntitlementTier) -> String {
        switch tier {
        case .free: return "Free"
        case .pro: return "Pro"
        case .msp: return "MSP"
        case .enterprise: return "Enterprise"
        }
    }

    /// One line, no drama. Contract section 7.6: every failure lands the user on the free
    /// tier, and none of them is an alert.
    static func describe(_ outcome: EntitlementFetchOutcome?) -> String? {
        switch outcome {
        case nil: return nil
        case .updated(.free): return "No organization license was found for this tenant."
        case .updated(let tier): return "\(tierName(tier)) license active."
        case .offline: return "Couldn't reach the license service. Your current license still applies."
        case .serverError: return "The license service is temporarily unavailable. Try again later."
        case .rejected: return "The license service returned something this app could not accept."
        }
    }
}
