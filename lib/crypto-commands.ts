import type { Terminal } from "@xterm/xterm"
import { CryptoEngine } from "./crypto-engine"

export class CryptoCommands {
  private terminal: Terminal
  private crypto: CryptoEngine

  constructor(terminal: Terminal) {
    this.terminal = terminal
    this.crypto = CryptoEngine.getInstance()
  }

  async executeCommand(command: string, args: string[]): Promise<void> {
    switch (command.toLowerCase()) {
      case "hash":
        await this.handleHash(args)
        break
      case "encrypt":
        await this.handleEncrypt(args)
        break
      case "decrypt":
        await this.handleDecrypt(args)
        break
      case "keygen":
        await this.handleKeyGen(args)
        break
      case "sign":
        await this.handleSign(args)
        break
      case "hmac":
        await this.handleHMAC(args)
        break
      case "password":
        await this.handlePasswordAnalysis(args)
        break
      case "blockchain":
        await this.handleBlockchain(args)
        break
      case "jwt":
        await this.handleJWT(args)
        break
      case "steganography":
      case "stego":
        await this.handleSteganography(args)
        break
      case "random":
        await this.handleRandom(args)
        break
      case "crypto-help":
        this.showCryptoHelp()
        break
      default:
        this.terminal.writeln(`\x1b[31mUnknown crypto command: ${command}\x1b[0m`)
    }
  }

  private async handleHash(args: string[]): Promise<void> {
    if (args.length < 1) {
      this.terminal.writeln("\x1b[31mUsage: hash <data> [algorithm] [salt]\x1b[0m")
      this.terminal.writeln("Algorithms: SHA-256, SHA-384, SHA-512, SHA-1, BLAKE2, MD5")
      return
    }

    const data = args[0]
    const algorithm = args[1] || "SHA-256"
    const salt = args[2]

    try {
      const result = await this.crypto.hash(data, algorithm, salt)

      const output = {
        operation: "hash",
        algorithm: result.algorithm,
        input: result.input,
        output: {
          hex: result.hex,
          base64: result.base64,
          length: result.length,
        },
        salt: result.salt,
        timestamp: result.timestamp,
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } catch (error) {
      this.terminal.writeln(`\x1b[31mHash error: ${error}\x1b[0m`)
    }
  }

  private async handleEncrypt(args: string[]): Promise<void> {
    if (args.length < 2) {
      this.terminal.writeln("\x1b[31mUsage: encrypt <data> <password>\x1b[0m")
      return
    }

    const data = args[0]
    const password = args[1]

    try {
      const result = await this.crypto.encrypt(data, password)

      const output = {
        operation: "encrypt",
        algorithm: result.algorithm,
        ciphertext: result.ciphertext,
        iv: result.iv,
        key_id: result.key_id,
        timestamp: result.timestamp,
        note: "Store this output safely - you need it for decryption",
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } catch (error) {
      this.terminal.writeln(`\x1b[31mEncryption error: ${error}\x1b[0m`)
    }
  }

  private async handleKeyGen(args: string[]): Promise<void> {
    const keySize = Number.parseInt(args[0]) || 2048

    if (![1024, 2048, 4096].includes(keySize)) {
      this.terminal.writeln("\x1b[31mSupported key sizes: 1024, 2048, 4096\x1b[0m")
      return
    }

    try {
      this.terminal.writeln("\x1b[33mGenerating RSA key pair... This may take a moment.\x1b[0m")

      const keyPair = await this.crypto.generateRSAKeyPair(keySize)

      const output = {
        operation: "keygen",
        algorithm: keyPair.algorithm,
        keySize: keyPair.keySize,
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey.substring(0, 100) + "...[truncated]",
        created: keyPair.created,
        note: "Private key truncated for display. Full keys stored in memory.",
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } catch (error) {
      this.terminal.writeln(`\x1b[31mKey generation error: ${error}\x1b[0m`)
    }
  }

  private async handleHMAC(args: string[]): Promise<void> {
    if (args.length < 2) {
      this.terminal.writeln("\x1b[31mUsage: hmac <data> <secret> [algorithm]\x1b[0m")
      return
    }

    const data = args[0]
    const secret = args[1]
    const algorithm = args[2] || "SHA-256"

    try {
      const hmac = await this.crypto.generateHMAC(data, secret, algorithm)

      const output = {
        operation: "hmac",
        algorithm: `HMAC-${algorithm}`,
        data,
        hmac,
        timestamp: new Date().toISOString(),
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } catch (error) {
      this.terminal.writeln(`\x1b[31mHMAC error: ${error}\x1b[0m`)
    }
  }

  private async handlePasswordAnalysis(args: string[]): Promise<void> {
    if (args.length < 1) {
      this.terminal.writeln("\x1b[31mUsage: password <password_to_analyze>\x1b[0m")
      return
    }

    const password = args[0]
    const analysis = this.crypto.analyzePasswordStrength(password)

    const output = {
      operation: "password_analysis",
      password: "*".repeat(password.length),
      analysis: {
        score: `${analysis.score}/8`,
        strength: analysis.strength,
        entropy: `${analysis.entropy.toFixed(2)} bits`,
        estimated_crack_time: analysis.crackTime,
        feedback: analysis.feedback,
      },
      timestamp: new Date().toISOString(),
    }

    this.terminal.writeln(JSON.stringify(output, null, 2))
  }

  private async handleBlockchain(args: string[]): Promise<void> {
    if (args.length < 1) {
      this.terminal.writeln("\x1b[31mUsage: blockchain <data1> [data2] [data3] ...\x1b[0m")
      return
    }

    try {
      this.terminal.writeln("\x1b[33mMining blockchain... This may take a moment.\x1b[0m")

      const result = await this.crypto.createHashChain(args)

      const output = {
        operation: "blockchain",
        blocks: result.chain.length,
        merkle_root: result.merkleRoot,
        chain: result.chain.map((block) => ({
          index: block.index,
          data: block.data,
          hash: block.hash.substring(0, 16) + "...",
          previous_hash: block.previousHash.substring(0, 16) + "...",
          nonce: block.nonce,
          timestamp: block.timestamp,
        })),
        full_hashes_note: "Full hashes truncated for display",
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } catch (error) {
      this.terminal.writeln(`\x1b[31mBlockchain error: ${error}\x1b[0m`)
    }
  }

  private async handleJWT(args: string[]): Promise<void> {
    if (args.length < 2) {
      this.terminal.writeln("\x1b[31mUsage: jwt <payload_json> <secret> [expires_in_seconds]\x1b[0m")
      this.terminal.writeln('Example: jwt \'{"user":"john","role":"admin"}\' mysecret 3600')
      return
    }

    try {
      const payload = JSON.parse(args[0])
      const secret = args[1]
      const expiresIn = Number.parseInt(args[2]) || 3600

      const token = await this.crypto.generateJWT(payload, secret, expiresIn)

      const output = {
        operation: "jwt_generate",
        payload,
        expires_in: `${expiresIn} seconds`,
        token,
        timestamp: new Date().toISOString(),
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } catch (error) {
      this.terminal.writeln(`\x1b[31mJWT error: ${error}\x1b[0m`)
    }
  }

  private async handleSteganography(args: string[]): Promise<void> {
    if (args.length < 1) {
      this.terminal.writeln("\x1b[31mUsage: stego hide <cover_text> <secret_text>\x1b[0m")
      this.terminal.writeln("\x1b[31m       stego extract <stego_text>\x1b[0m")
      return
    }

    const operation = args[0]

    if (operation === "hide" && args.length >= 3) {
      const coverText = args[1]
      const secretText = args[2]

      const stegoText = this.crypto.hideTextInText(coverText, secretText)

      const output = {
        operation: "steganography_hide",
        cover_text: coverText,
        secret_text: secretText,
        stego_text: stegoText,
        note: "Secret text hidden using zero-width characters",
        timestamp: new Date().toISOString(),
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } else if (operation === "extract" && args.length >= 2) {
      const stegoText = args[1]
      const extractedText = this.crypto.extractHiddenText(stegoText)

      const output = {
        operation: "steganography_extract",
        stego_text: stegoText,
        extracted_text: extractedText,
        timestamp: new Date().toISOString(),
      }

      this.terminal.writeln(JSON.stringify(output, null, 2))
    } else {
      this.terminal.writeln("\x1b[31mInvalid steganography operation\x1b[0m")
    }
  }

  private async handleRandom(args: string[]): Promise<void> {
    const length = Number.parseInt(args[0]) || 32
    const format = args[1] || "hex"

    if (!["hex", "base64", "bytes"].includes(format)) {
      this.terminal.writeln("\x1b[31mSupported formats: hex, base64, bytes\x1b[0m")
      return
    }

    const randomData = this.crypto.generateSecureRandom(length, format as any)

    const output = {
      operation: "secure_random",
      length,
      format,
      data: randomData,
      entropy: `${length * 8} bits`,
      timestamp: new Date().toISOString(),
    }

    this.terminal.writeln(JSON.stringify(output, null, 2))
  }

  private showCryptoHelp(): void {
    const commands = [
      { cmd: "hash <data> [algo] [salt]", desc: "Generate cryptographic hash" },
      { cmd: "encrypt <data> <password>", desc: "AES-256-GCM encryption" },
      { cmd: "decrypt <encrypted_json> <password>", desc: "AES-256-GCM decryption" },
      { cmd: "keygen [keysize]", desc: "Generate RSA key pair (1024/2048/4096)" },
      { cmd: "sign <data> <private_key>", desc: "Create digital signature" },
      { cmd: "hmac <data> <secret> [algo]", desc: "Generate HMAC" },
      { cmd: "password <password>", desc: "Analyze password strength" },
      { cmd: "blockchain <data1> [data2]...", desc: "Create proof-of-work blockchain" },
      { cmd: "jwt <payload> <secret> [expires]", desc: "Generate JWT token" },
      { cmd: "stego hide <cover> <secret>", desc: "Hide text in text" },
      { cmd: "stego extract <stego_text>", desc: "Extract hidden text" },
      { cmd: "random [length] [format]", desc: "Generate secure random data" },
    ]

    this.terminal.writeln("\x1b[36m╔══════════════════════════════════════════════════════════════╗\x1b[0m")
    this.terminal.writeln("\x1b[36m║                    Cryptography Commands                     ║\x1b[0m")
    this.terminal.writeln("\x1b[36m╚══════════════════════════════════════════════════════════════╝\x1b[0m")
    this.terminal.writeln("")

    commands.forEach(({ cmd, desc }) => {
      this.terminal.writeln(`  \x1b[33m${cmd.padEnd(35)}\x1b[0m ${desc}`)
    })

    this.terminal.writeln("")
    this.terminal.writeln("\x1b[32mSupported Hash Algorithms:\x1b[0m")
    this.terminal.writeln("  SHA-256, SHA-384, SHA-512, SHA-1, BLAKE2, MD5")
    this.terminal.writeln("")
    this.terminal.writeln("\x1b[32mFeatures:\x1b[0m")
    this.terminal.writeln("  • Military-grade encryption (AES-256-GCM)")
    this.terminal.writeln("  • RSA public-key cryptography")
    this.terminal.writeln("  • Digital signatures and HMAC")
    this.terminal.writeln("  • Password strength analysis")
    this.terminal.writeln("  • Blockchain simulation with PoW")
    this.terminal.writeln("  • JWT token generation")
    this.terminal.writeln("  • Steganography (text hiding)")
    this.terminal.writeln("  • Cryptographically secure random generation")
    this.terminal.writeln("")
  }
}
