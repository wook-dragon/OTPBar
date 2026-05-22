import Foundation
import Security
import AuthenticatorCore

public final class KeychainAccountStore: AccountStore {
    public enum KeychainError: Error, CustomStringConvertible {
        case osStatus(OSStatus)
        case decodingFailed(Error)
        case encodingFailed(Error)

        public var description: String {
            switch self {
            case .osStatus(let status):
                let msg = SecCopyErrorMessageString(status, nil) as String? ?? "알 수 없는 Keychain 오류"
                return "Keychain 오류 (\(status)): \(msg)"
            case .decodingFailed(let error):
                return "Keychain 데이터 디코딩 실패: \(error)"
            case .encodingFailed(let error):
                return "Keychain 데이터 인코딩 실패: \(error)"
            }
        }
    }

    private let service: String
    private let legacyService: String?
    private let account: String

    public init(
        service: String = "dev.wook-dragon.Authenticator",
        legacyService: String? = "kr.danbiedu.wook.Authenticator",
        account: String = "accounts"
    ) {
        self.service = service
        self.legacyService = legacyService
        self.account = account
    }

    public func load() throws -> [OTPAccount] {
        if let accounts = try read(from: service), !accounts.isEmpty {
            return accounts
        }
        // 옛 service ID에 저장된 데이터가 있으면 새 service ID로 옮기고 옛 entry는 삭제한다.
        if let legacy = legacyService,
           let accounts = try read(from: legacy),
           !accounts.isEmpty {
            try save(accounts)
            try? delete(from: legacy)
            return accounts
        }
        return []
    }

    public func save(_ accounts: [OTPAccount]) throws {
        let data: Data
        do {
            data = try JSONEncoder().encode(accounts)
        } catch {
            throw KeychainError.encodingFailed(error)
        }

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
        ]
        let updateStatus = SecItemUpdate(query(for: service) as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus == errSecItemNotFound {
            var addAttributes = query(for: service)
            addAttributes.merge(attributes) { _, new in new }
            let addStatus = SecItemAdd(addAttributes as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw KeychainError.osStatus(addStatus) }
            return
        }
        throw KeychainError.osStatus(updateStatus)
    }

    public func reset() throws {
        try delete(from: service)
    }

    // MARK: - 내부

    private func query(for svc: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: svc,
            kSecAttrAccount as String: account,
        ]
    }

    private func read(from svc: String) throws -> [OTPAccount]? {
        var q = query(for: svc)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.osStatus(status)
        }
        do {
            return try JSONDecoder().decode([OTPAccount].self, from: data)
        } catch {
            throw KeychainError.decodingFailed(error)
        }
    }

    private func delete(from svc: String) throws {
        let status = SecItemDelete(query(for: svc) as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.osStatus(status)
        }
    }
}
