import Foundation
import CommonCrypto // For insecure MD5

class Vulnerabilities {
    
    // 1. Insecure Randomness (Semgrep)
    func generateRandomNumber() -> UInt32 {
        // arc4random is considered insecure for cryptographic purposes
        return arc4random()
    }
    
    // 2. Insecure Hashing (Semgrep / CodeQL)
    func md5Hash(string: String) -> String {
        let length = Int(CC_MD5_DIGEST_LENGTH)
        var digest = [UInt8](repeating: 0, count: length)
        
        if let d = string.data(using: .utf8) {
            _ = d.withUnsafeBytes { body -> String in
                CC_MD5(body.baseAddress, CC_LONG(d.count), &digest)
                return ""
            }
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
    
    // 3. Command Injection / Taint Path (CodeQL)
    func executeCommand(userInput: String) {
        let task = Process()
        task.launchPath = "/bin/sh"
        // Untrusted user input flowing directly into command execution
        task.arguments = ["-c", userInput]
        task.launch()
    }
    
    // 4. Hardcoded Database Credentials (Semgrep)
    func connectToDatabase() {
        let dbUser = "admin"
        let dbPassword = "superSecretPassword123"
        print("Connecting to DB with \(dbUser):\(dbPassword)")
    }
}
