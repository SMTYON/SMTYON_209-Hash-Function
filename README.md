# SMTYON_209-Hash-Function

Secure Password Hashing System (Linux Edition)
A memory-hard password hashing implementation designed for Linux systems with strong security properties and resistance to various cryptographic attacks.

🛡️ Security Features
Memory-Hard KDF: Defeats GPU/ASIC parallel attacks

128-bit Operations: Cryptographic operations with Mersenne prime modulus (2¹²⁷ - 1)

Strong Input Validation: Enforced 16-256 character passwords

Side-Channel Resistance: Constant-time operations and secure memory handling

Cryptographic Randomness: Uses /dev/urandom for secure salt generation

Pepper Protection: Additional secret value not stored with hashes

Versioned Output: Supports future algorithm upgrades

📋 Requirements
Compiler: GCC or Clang with C++11 support

Platform: Linux (uses /dev/urandom)

Memory: Minimum 4MB RAM available for hashing operations

CPU: Modern processor with 64-bit support

🚀 Installation & Compilation
bash
# Clone or download the source code
git clone <repository-url>
cd secure-password-hash

# Compile with GCC
g++ -o password_hash password_hash.cpp -std=c++11 -pthread -O2

# Or compile with Clang
clang++ -o password_hash password_hash.cpp -std=c++11 -pthread -O2
💻 Usage
Basic Hashing
cpp
#include "password_hash.hpp" // If you create a header

// Initialize security parameters (do once at application start)
initialize_security_parameters();

// Generate a secure salt
__uint128_t salt = generate_strong_salt();

// Hash a password (returns string representation)
std::string hashed_password = SMTYON_209("MySecurePassword123!", salt, true);
Integration Example
cpp
// User registration
std::string hashPassword(const std::string& password) {
    __uint128_t salt = generate_strong_salt();
    std::string hash = SMTYON_209(password, salt, true); // High security mode
    // Store both hash and salt (but NOT pepper)
    return hash;
}

// Password verification
bool verifyPassword(const std::string& password, const std::string& stored_hash, __uint128_t stored_salt) {
    std::string computed_hash = SMTYON_209(password, stored_salt, true);
    return constant_time_compare(computed_hash, stored_hash);
}
⚙️ Configuration
Security Parameters
cpp
// Modify these constants in the code for your security requirements:
const size_t MEMORY_BUFFER_SIZE = 1 << 22; // 4MB (adjust for your system)
const int BASE_ITERATIONS = 300000;        // Base computational cost
const uint8_t HASH_VERSION = 0x04;         // Algorithm version
Pepper Management
Important: The pepper must be kept secret and secure:

Generate randomly for each deployment

Store in secure configuration or HSM

Rotate periodically (recommended quarterly)

cpp
// Pepper is automatically generated with secure random values
initialize_security_parameters(); // Call this once at startup
🧪 Testing
The included test harness verifies functionality:

bash
./password_hash
# Output:
# Hash 1: 28423393712738429182374661928374619283
# Hash 2: 28423393712738429182374661928374619283
# Match: YES
# Time: 1243 ms
🔧 Performance Tuning
Adjust these parameters based on your security requirements:

Memory Usage: Modify MEMORY_BUFFER_SIZE

Iteration Count: Adjust BASE_ITERATIONS

Security Level: Use high_security=true for sensitive applications

Typical performance: 1000-2000ms per hash on modern hardware

⚠️ Security Considerations
Critical Notes
Custom Algorithm: This is a custom implementation - prefer established algorithms (Argon2, bcrypt, scrypt) for production

Pepper Security: The pepper must remain secret and never be stored with hashes

Salt Management: Each password must have a unique, random salt

Runtime Analysis: Monitor timing to prevent DoS attacks

Recommended Production Alternatives
bash
# Instead of custom implementation, consider:
# Install libsodium (for Argon2)
sudo apt-get install libsodium-dev

# Or use OpenSSL (for PBKDF2)
sudo apt-get install libssl-dev
🐛 Debugging
Compile with debug symbols:

bash
g++ -o password_hash_debug password_hash.cpp -std=c++11 -pthread -g
Common issues:

Compilation errors: Ensure C++11 support (-std=c++11)

Permission denied: Check /dev/urandom access

Memory errors: Reduce MEMORY_BUFFER_SIZE if limited RAM

📊 Algorithm Details
Version History
v0.04: Current version (SMTYON_209)

v0.02: Previous Windows version

Cryptographic Properties
Modulus: Mersenne prime 2¹²⁷ - 1

Memory: 4MB working memory

Iterations: 300,000-600,000+ (scales with password length)

Output: 128-bit integer encoded as decimal string

📄 License
This software is provided for educational and research purposes. Use in production systems requires thorough security audit.

🤝 Contributing
Security vulnerabilities: Please disclose responsibly

Improvements: Submit pull requests with detailed explanations

Testing: Include performance benchmarks and security analysis

🆘 Support
For issues and questions:

Check compilation requirements

Verify Linux compatibility

Review security considerations before deployment

Disclaimer: This implementation is for educational purposes. Always use well-vetted, standardized cryptographic algorithms for production systems.
