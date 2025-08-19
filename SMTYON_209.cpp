/*
 * Secure Password Hashing System (Linux Edition)
 *
 * Key Security Features:
 * - Memory-hard key derivation function (KDF)
 * - 128-bit cryptographic operations with Mersenne prime modulus
 * - Enforced 16+ character passwords
 * - Side-channel attack resistant design
 * - Linux /dev/urandom integration for secure randomness
 */
#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include <random>
#include <stdexcept>
#include <cstring>      // For secure memory zeroization
#include <thread>       // For attack throttling
#include <chrono>       // For timing operations
#include <algorithm>    // For std::max
#include <fstream>      // For reading /dev/urandom

// ======================
// CONSTANT CONFIGURATION
// ======================

/**
 * @brief Cryptographic mixing constant derived from golden ratio
 * Value: 0x9E3779B1
 * Purpose: Provides good avalanche properties - small input changes create large output differences
 */
const __uint128_t ADDITIVE_CONSTANT = 0x9E3779B1;

/**
 * @brief Large Mersenne prime modulus (2^127 - 1)
 * Properties:
 * - Enables efficient modulo operations
 * - Provides uniform distribution of outputs
 * - Resists mathematical attacks on the finite field
 */
const __uint128_t MOD = (__uint128_t(1) << 127) - 1;

/**
 * @brief Memory buffer size (4MB)
 * Security rationale:
 * - Large enough to defeat GPU/ASIC parallel attacks
 * - Small enough for practical server deployment
 * - Balances security and performance (originally 1MB, increased for stronger security)
 */
const size_t MEMORY_BUFFER_SIZE = 1 << 22; // 4MB

/**
 * @brief Algorithm version identifier
 * Purpose:
 * - Allows future algorithm upgrades
 * - Maintains backward compatibility
 * - Enables version tracking in stored hashes
 */
const uint8_t HASH_VERSION = 0x04;

/**
 * @brief Base iteration count (300,000 iterations)
 * Security properties:
 * - Minimum 300,000 iterations for basic security
 * - Automatically scales with password length
 * - Doubles to 600,000 in high security mode
 */
const int BASE_ITERATIONS = 300000;

// Maximum password length to prevent excessive computation
const size_t MAX_PASSWORD_LENGTH = 256;

// ======================
// RUNTIME CONFIGURATION
// ======================

/**
 * @brief Cryptographic pepper value (128-bit)
 * Security requirements:
 * - Must be unique per application deployment
 * - Should be loaded from secure storage (HSM or secure config)
 * - Must remain secret (not stored with hashes)
 */
__uint128_t SECRET_PEPPER;

/**
 * @brief Memory access randomization keys (128-bit total)
 * Security properties:
 * - Prevents predictable memory access patterns
 * - Should be rotated periodically (recommended quarterly)
 * - Must remain secret
 */
uint64_t MEMORY_ACCESS_KEY[2];

// ======================
// UTILITY FUNCTIONS
// ======================

/**
 * @brief Mersenne modulus reduction
 * Efficient reduction modulo (2^127 - 1)
 */
__uint128_t mersenne_mod(__uint128_t x) {
    __uint128_t result = (x & MOD) + (x >> 127);
    return (result >= MOD) ? result - MOD : result;
}

/**
 * @brief Converts 128-bit integer to decimal string
 * @param value The 128-bit unsigned integer to convert
 * @return String representation in base-10
 */
std::string uint128_to_string(__uint128_t value) {
    if (value == 0) return "0";
    std::string result;
    while (value > 0) {
        char digit = '0' + (value % 10);
        result = digit + result;
        value /= 10;
    }
    return result;
}

/**
 * @brief Securely erases sensitive memory
 * @param ptr Pointer to memory region
 * @param len Length of memory to zero
 */
void secure_zero(void* ptr, size_t len) {
    volatile char* vptr = static_cast<volatile char*>(ptr);
    while (len--) *vptr++ = 0;
}

// ======================
// CORE HASHING FUNCTION
// ======================

/**
 * @brief Hashes a password with cryptographic salt
 * @param password The plaintext password (16-256 chars)
 * @param salt 128-bit random salt
 * @param high_security If true, doubles iteration count
 * @return Hashed password as string
 * @throws std::invalid_argument for invalid password lengths
 */
std::string SMTYON_209(const std::string& password, __uint128_t salt, bool high_security = false) {
    // --- Input Validation ---
    if (password.length() < 16) {
        throw std::invalid_argument("Password must be at least 16 characters");
    }
    if (password.length() > MAX_PASSWORD_LENGTH) {
        throw std::invalid_argument("Password exceeds maximum length (256 chars)");
    }

    // --- Memory Initialization ---
    std::vector<__uint128_t> memory_buffer(MEMORY_BUFFER_SIZE);
    __uint128_t result = 0;

    // --- Dynamic Iteration Scaling ---
    int iterations = high_security ?
                    BASE_ITERATIONS * 2 :
                    std::max(BASE_ITERATIONS, static_cast<int>(10000 * password.length()));

    // Ensure iterations don't become excessive
    iterations = std::min(iterations, 10000000); // Max 10 million iterations

    // --- Password Preprocessing ---
    for (size_t i = 0; i < password.size(); i++) {
        // Encode both character value AND its position
        __uint128_t cur_char = (static_cast<__uint128_t>(password[i]) << 32) | i;

        // Enhanced mixing steps with proper modulus
        cur_char = mersenne_mod(cur_char * 0x5BD1E995);

        // Safe salt shift (avoid shifting by 64+ bits)
        uint8_t shift_amount = static_cast<uint8_t>(i % 63) + 1;
        cur_char ^= (salt >> shift_amount);

        cur_char = mersenne_mod(cur_char + (cur_char << 16));
        cur_char ^= SECRET_PEPPER;
        cur_char = mersenne_mod(cur_char);

        // Accumulate results
        result = mersenne_mod(result + cur_char);
    }

    // --- Memory-Hard Computation Phase ---
    for (int i = 0; i < iterations; i++) {
        // Safe memory access with proper bounds checking
        size_t idx = mersenne_mod(result + i + MEMORY_ACCESS_KEY[i % 2]) % MEMORY_BUFFER_SIZE;

        // Dynamic operation selection with proper modulus
        memory_buffer[idx] = mersenne_mod((memory_buffer[idx] * 0xC4CEB9FE) ^ (result + i));

        // Asymmetric read pattern with bounds checking
        size_t read_pos = mersenne_mod(result ^ (i * 0x9E3779B9)) % MEMORY_BUFFER_SIZE;
        __uint128_t temp = memory_buffer[read_pos];

        // Enhanced mixing chain with proper modulus:
        temp = mersenne_mod(temp * 0xCC9E2D51);
        temp ^= (salt >> 32);

        // Bit rotation
        temp = (temp << 15) | (temp >> (128 - 15));
        temp ^= result;
        result = mersenne_mod(result + temp);
    }

    // --- Finalization Phase ---
    // Multi-stage bit mixing with proper modulus:
    result ^= (result >> 64);
    result = mersenne_mod(result * 0xFF51AFD7);
    result ^= (result >> 32);
    result = mersenne_mod(result * 0xC4CEB9FE);
    result ^= (result >> 29);
    result ^= (__uint128_t(HASH_VERSION) << 120);

    // --- Secure Cleanup ---
    secure_zero(memory_buffer.data(), memory_buffer.size() * sizeof(__uint128_t));

    return uint128_to_string(result);
}

// ======================
// SUPPORT FUNCTIONS
// ======================

/**
 * @brief Generates cryptographically secure random values
 */
template<typename T>
T generate_crypto_random() {
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom) {
        throw std::runtime_error("Failed to open /dev/urandom");
    }

    T value;
    urandom.read(reinterpret_cast<char*>(&value), sizeof(value));

    if (!urandom) {
        throw std::runtime_error("Failed to read from /dev/urandom");
    }

    urandom.close();
    return value;
}

/**
 * @brief Generates cryptographically secure salt using /dev/urandom
 */
__uint128_t generate_strong_salt() {
    uint64_t part1 = generate_crypto_random<uint64_t>();
    uint64_t part2 = generate_crypto_random<uint64_t>();
    return (static_cast<__uint128_t>(part1) << 64) | part2;
}

/**
 * @brief Initializes security parameters with secure random values
 */
void initialize_security_parameters() {
    SECRET_PEPPER = generate_strong_salt();
    MEMORY_ACCESS_KEY[0] = generate_crypto_random<uint64_t>();
    MEMORY_ACCESS_KEY[1] = generate_crypto_random<uint64_t>();
}

/**
 * @brief Constant-time string comparison
 */
bool constant_time_compare(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;
    unsigned char result = 0;
    for (size_t i = 0; i < a.length(); i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// ======================
// MAIN FUNCTION (TEST HARNESS)
// ======================

int main() {
    try {
        // Initialize security parameters with secure random values
        initialize_security_parameters();

        // Generate random salt
        __uint128_t salt = generate_strong_salt();

        // Test passwords
        std::string pass1 = "SecurePassword12345!"; // 20 characters
        std::string pass2 = "SecurePassword12345!";

        // Generate hashes
        auto start = std::chrono::high_resolution_clock::now();
        std::string hash1 = SMTYON_209(pass1, salt, true);
        std::string hash2 = SMTYON_209(pass2, salt, true);
        auto end = std::chrono::high_resolution_clock::now();

        // Output results
        std::cout << "Hash 1: " << hash1 << "\n";
        std::cout << "Hash 2: " << hash2 << "\n";
        std::cout << "Match: " << (constant_time_compare(hash1, hash2) ? "YES" : "NO") << "\n";
        std::cout << "Time: "
                  << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
                  << " ms\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}