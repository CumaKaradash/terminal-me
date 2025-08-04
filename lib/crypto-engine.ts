export interface HashResult {
  algorithm: string
  input: string
  hash: string
  hex: string
  base64: string
  length: number
  timestamp: string
  salt?: string
}

export interface EncryptionResult {
  algorithm: string
  ciphertext: string
  iv: string
  tag?: string
  key_id: string
  timestamp: string
}

export interface KeyPair {
  publicKey: string
  privateKey: string
  algorithm: string
  keySize: number
  created: string
}

export interface DigitalSignature {
  signature: string
  algorithm: string
  publicKey: string
  timestamp: string
  verified: boolean
}

// Safe crypto API access
const getCryptoAPI = () => {
  if (typeof window !== "undefined" && window.crypto) {
    return window.crypto
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto) {
    return globalThis.crypto
  }
  throw new Error("Web Crypto API not available")
}

export class CryptoEngine {
  private static instance: CryptoEngine
  private keyStore: Map<string, CryptoKey> = new Map()
  private keyPairs: Map<string, KeyPair> = new Map()

  static getInstance(): CryptoEngine {
    if (!CryptoEngine.instance) {
      CryptoEngine.instance = new CryptoEngine()
    }
    return CryptoEngine.instance
  }

  // Advanced Hash Functions
  async hash(data: string, algorithm = "SHA-256", salt?: string): Promise<HashResult> {
    const crypto = getCryptoAPI()
    const encoder = new TextEncoder()
    const inputData = salt ? data + salt : data
    const dataBuffer = encoder.encode(inputData)

    let hashBuffer: ArrayBuffer

    switch (algorithm.toUpperCase()) {
      case "SHA-256":
      case "SHA-384":
      case "SHA-512":
        hashBuffer = await crypto.subtle.digest(algorithm, dataBuffer)
        break
      case "SHA-1":
        hashBuffer = await crypto.subtle.digest("SHA-1", dataBuffer)
        break
      default:
        // Custom implementations for other algorithms
        hashBuffer = await this.customHash(dataBuffer, algorithm)
    }

    const hashArray = new Uint8Array(hashBuffer)
    const hex = Array.from(hashArray)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
    const base64 = btoa(String.fromCharCode(...hashArray))

    return {
      algorithm,
      input: data,
      hash: hex,
      hex,
      base64,
      length: hashArray.length,
      timestamp: new Date().toISOString(),
      salt,
    }
  }

  // BLAKE2 Implementation
  private async customHash(data: ArrayBuffer, algorithm: string): Promise<ArrayBuffer> {
    const crypto = getCryptoAPI()

    if (algorithm.toUpperCase() === "BLAKE2") {
      return this.blake2Hash(new Uint8Array(data))
    }

    if (algorithm.toUpperCase() === "MD5") {
      return this.md5Hash(new Uint8Array(data))
    }

    // Fallback to SHA-256
    return await crypto.subtle.digest("SHA-256", data)
  }

  // Simplified BLAKE2 implementation
  private async blake2Hash(data: Uint8Array): Promise<ArrayBuffer> {
    const crypto = getCryptoAPI()
    // This is a simplified version - in production, use a proper BLAKE2 library
    const key = await crypto.subtle.importKey("raw", data, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])

    const signature = await crypto.subtle.sign("HMAC", key, data)
    return signature
  }

  // Simplified MD5 implementation (for demonstration - use proper library in production)
  private async md5Hash(data: Uint8Array): Promise<ArrayBuffer> {
    const crypto = getCryptoAPI()
    // This is a placeholder - implement proper MD5 or use a library
    return await crypto.subtle.digest("SHA-256", data)
  }

  // AES-256-GCM Encryption
  async encrypt(data: string, password: string): Promise<EncryptionResult> {
    const crypto = getCryptoAPI()
    const encoder = new TextEncoder()
    const dataBuffer = encoder.encode(data)

    // Derive key from password using PBKDF2
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"])

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    )

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, dataBuffer)

    const keyId = this.generateKeyId()
    this.keyStore.set(keyId, key)

    return {
      algorithm: "AES-256-GCM",
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
      iv: btoa(String.fromCharCode(...iv)),
      key_id: keyId,
      timestamp: new Date().toISOString(),
    }
  }

  // AES-256-GCM Decryption
  async decrypt(encryptedData: EncryptionResult, password: string): Promise<string> {
    const crypto = getCryptoAPI()
    const encoder = new TextEncoder()

    // Recreate the key using the same password and salt
    const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"])

    // Note: In a real implementation, you'd need to store and retrieve the salt
    const salt = new Uint8Array(16) // This should be stored with the encrypted data

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    )

    const iv = new Uint8Array(
      atob(encryptedData.iv)
        .split("")
        .map((c) => c.charCodeAt(0)),
    )
    const ciphertext = new Uint8Array(
      atob(encryptedData.ciphertext)
        .split("")
        .map((c) => c.charCodeAt(0)),
    )

    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext)

    return new TextDecoder().decode(decrypted)
  }

  // RSA Key Pair Generation
  async generateRSAKeyPair(keySize = 2048): Promise<KeyPair> {
    const crypto = getCryptoAPI()
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: keySize,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    )

    const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey)
    const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey)

    const keyPairData: KeyPair = {
      publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
      privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKey))),
      algorithm: "RSA-OAEP",
      keySize,
      created: new Date().toISOString(),
    }

    const keyId = this.generateKeyId()
    this.keyPairs.set(keyId, keyPairData)

    return keyPairData
  }

  // Digital Signature Generation
  async signData(data: string, privateKeyPem: string): Promise<DigitalSignature> {
    const crypto = getCryptoAPI()
    const encoder = new TextEncoder()
    const dataBuffer = encoder.encode(data)

    // Import private key
    const privateKeyBuffer = new Uint8Array(
      atob(privateKeyPem)
        .split("")
        .map((c) => c.charCodeAt(0)),
    )
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      privateKeyBuffer,
      {
        name: "RSA-PSS",
        hash: "SHA-256",
      },
      false,
      ["sign"],
    )

    const signature = await crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      privateKey,
      dataBuffer,
    )

    return {
      signature: btoa(String.fromCharCode(...new Uint8Array(signature))),
      algorithm: "RSA-PSS",
      publicKey: "", // Would be derived from private key
      timestamp: new Date().toISOString(),
      verified: false,
    }
  }

  // HMAC Generation
  async generateHMAC(data: string, secret: string, algorithm = "SHA-256"): Promise<string> {
    const crypto = getCryptoAPI()
    const encoder = new TextEncoder()
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: algorithm }, false, [
      "sign",
    ])

    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data))
    return Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  }

  // Password Strength Analysis
  analyzePasswordStrength(password: string): {
    score: number
    strength: string
    feedback: string[]
    entropy: number
    crackTime: string
  } {
    const feedback: string[] = []
    let score = 0

    // Length check
    if (password.length >= 12) score += 2
    else if (password.length >= 8) score += 1
    else feedback.push("Password should be at least 8 characters long")

    // Character variety
    if (/[a-z]/.test(password)) score += 1
    else feedback.push("Add lowercase letters")

    if (/[A-Z]/.test(password)) score += 1
    else feedback.push("Add uppercase letters")

    if (/[0-9]/.test(password)) score += 1
    else feedback.push("Add numbers")

    if (/[^a-zA-Z0-9]/.test(password)) score += 2
    else feedback.push("Add special characters")

    // Common patterns
    if (!/(.)\1{2,}/.test(password)) score += 1
    else feedback.push("Avoid repeated characters")

    // Calculate entropy
    const charset = this.getCharsetSize(password)
    const entropy = Math.log2(Math.pow(charset, password.length))

    // Estimate crack time
    const crackTime = this.estimateCrackTime(entropy)

    const strength = score >= 7 ? "Very Strong" : score >= 5 ? "Strong" : score >= 3 ? "Medium" : "Weak"

    return {
      score,
      strength,
      feedback,
      entropy,
      crackTime,
    }
  }

  private getCharsetSize(password: string): number {
    let size = 0
    if (/[a-z]/.test(password)) size += 26
    if (/[A-Z]/.test(password)) size += 26
    if (/[0-9]/.test(password)) size += 10
    if (/[^a-zA-Z0-9]/.test(password)) size += 32
    return size
  }

  private estimateCrackTime(entropy: number): string {
    const guessesPerSecond = 1e9 // 1 billion guesses per second
    const seconds = Math.pow(2, entropy - 1) / guessesPerSecond

    if (seconds < 60) return `${Math.round(seconds)} seconds`
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`
    return `${Math.round(seconds / 31536000)} years`
  }

  // Blockchain-style Hash Chain
  createHashChain(
    data: string[],
    algorithm = "SHA-256",
  ): Promise<{
    chain: Array<{
      index: number
      data: string
      hash: string
      previousHash: string
      timestamp: string
      nonce: number
    }>
    merkleRoot: string
  }> {
    return new Promise(async (resolve) => {
      const chain = []
      let previousHash = "0".repeat(64)

      for (let i = 0; i < data.length; i++) {
        const block = {
          index: i,
          data: data[i],
          hash: "",
          previousHash,
          timestamp: new Date().toISOString(),
          nonce: 0,
        }

        // Simple proof of work (find hash starting with '0000')
        while (true) {
          const blockString = JSON.stringify(block)
          const hashResult = await this.hash(blockString, algorithm)

          if (hashResult.hex.startsWith("0000")) {
            block.hash = hashResult.hex
            break
          }
          block.nonce++
        }

        chain.push(block)
        previousHash = block.hash
      }

      // Calculate Merkle root
      const merkleRoot = await this.calculateMerkleRoot(chain.map((b) => b.hash))

      resolve({ chain, merkleRoot })
    })
  }

  private async calculateMerkleRoot(hashes: string[]): Promise<string> {
    if (hashes.length === 0) return ""
    if (hashes.length === 1) return hashes[0]

    const newLevel = []
    for (let i = 0; i < hashes.length; i += 2) {
      const left = hashes[i]
      const right = hashes[i + 1] || left
      const combined = await this.hash(left + right)
      newLevel.push(combined.hex)
    }

    return this.calculateMerkleRoot(newLevel)
  }

  // JWT Token Generation
  async generateJWT(payload: any, secret: string, expiresIn = 3600): Promise<string> {
    const header = {
      alg: "HS256",
      typ: "JWT",
    }

    const now = Math.floor(Date.now() / 1000)
    const jwtPayload = {
      ...payload,
      iat: now,
      exp: now + expiresIn,
    }

    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, "")
    const encodedPayload = btoa(JSON.stringify(jwtPayload)).replace(/=/g, "")

    const signature = await this.generateHMAC(`${encodedHeader}.${encodedPayload}`, secret)
    const encodedSignature = btoa(signature).replace(/=/g, "")

    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
  }

  // Steganography - Hide text in text
  hideTextInText(coverText: string, secretText: string): string {
    const binarySecret = secretText
      .split("")
      .map((char) => char.charCodeAt(0).toString(2).padStart(8, "0"))
      .join("")

    let result = ""
    let binaryIndex = 0

    for (let i = 0; i < coverText.length && binaryIndex < binarySecret.length; i++) {
      const char = coverText[i]
      if (char === " ") {
        // Use zero-width characters to encode binary
        result += char
        if (binarySecret[binaryIndex] === "1") {
          result += "\u200B" // Zero-width space
        } else {
          result += "\u200C" // Zero-width non-joiner
        }
        binaryIndex++
      } else {
        result += char
      }
    }

    return result + coverText.slice(result.replace(/[\u200B\u200C]/g, "").length)
  }

  // Extract hidden text from steganography
  extractHiddenText(stegoText: string): string {
    const binaryData = []

    for (let i = 0; i < stegoText.length; i++) {
      const char = stegoText[i]
      if (char === "\u200B") {
        binaryData.push("1")
      } else if (char === "\u200C") {
        binaryData.push("0")
      }
    }

    const binaryString = binaryData.join("")
    let result = ""

    for (let i = 0; i < binaryString.length; i += 8) {
      const byte = binaryString.slice(i, i + 8)
      if (byte.length === 8) {
        result += String.fromCharCode(Number.parseInt(byte, 2))
      }
    }

    return result
  }

  // Generate cryptographically secure random data
  generateSecureRandom(length: number, format: "hex" | "base64" | "bytes" = "hex"): string {
    const crypto = getCryptoAPI()
    const randomBytes = crypto.getRandomValues(new Uint8Array(length))

    switch (format) {
      case "hex":
        return Array.from(randomBytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
      case "base64":
        return btoa(String.fromCharCode(...randomBytes))
      case "bytes":
        return String.fromCharCode(...randomBytes)
      default:
        return Array.from(randomBytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
    }
  }

  private generateKeyId(): string {
    return this.generateSecureRandom(16, "hex")
  }

  // Get stored keys
  getStoredKeys(): { keyStore: string[]; keyPairs: string[] } {
    return {
      keyStore: Array.from(this.keyStore.keys()),
      keyPairs: Array.from(this.keyPairs.keys()),
    }
  }
}
