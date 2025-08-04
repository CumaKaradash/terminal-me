import type { Terminal } from "@xterm/xterm"
import { useTerminalStore } from "./terminal-store"
import { CryptoCommands } from "./crypto-commands"

export class CommandProcessor {
  private terminal: Terminal
  private currentLine = ""
  private cursorPosition = 0
  private store = useTerminalStore.getState()
  private cryptoCommands: CryptoCommands

  constructor(terminal: Terminal) {
    this.terminal = terminal
    this.cryptoCommands = new CryptoCommands(terminal)
    this.setupEventHandlers()
  }

  private setupEventHandlers() {
    this.terminal.onData((data) => {
      const code = data.charCodeAt(0)

      // Handle special keys
      if (code === 13) {
        // Enter
        this.handleEnter()
      } else if (code === 127) {
        // Backspace
        this.handleBackspace()
      } else if (code === 27) {
        // Escape sequences
        this.handleEscapeSequence(data)
      } else if (code === 9) {
        // Tab
        this.handleTab()
      } else if (code >= 32 && code <= 126) {
        // Printable characters
        this.handlePrintableChar(data)
      }
    })
  }

  private handleEnter() {
    this.terminal.writeln("")

    if (this.currentLine.trim()) {
      this.store.addToHistory(this.currentLine.trim())
      this.executeCommand(this.currentLine.trim())
    }

    this.currentLine = ""
    this.cursorPosition = 0
    this.showPrompt()
  }

  private handleBackspace() {
    if (this.cursorPosition > 0) {
      this.currentLine =
        this.currentLine.slice(0, this.cursorPosition - 1) + this.currentLine.slice(this.cursorPosition)
      this.cursorPosition--
      this.refreshLine()
    }
  }

  private handleEscapeSequence(data: string) {
    if (data === "\x1b[A") {
      // Up arrow
      this.handleHistoryUp()
    } else if (data === "\x1b[B") {
      // Down arrow
      this.handleHistoryDown()
    } else if (data === "\x1b[C") {
      // Right arrow
      if (this.cursorPosition < this.currentLine.length) {
        this.cursorPosition++
        this.terminal.write("\x1b[C")
      }
    } else if (data === "\x1b[D") {
      // Left arrow
      if (this.cursorPosition > 0) {
        this.cursorPosition--
        this.terminal.write("\x1b[D")
      }
    }
  }

  private handleTab() {
    const words = this.currentLine.split(" ")
    const currentWord = words[words.length - 1]

    if (words.length === 1) {
      // Command completion
      const commands = [
        "help",
        "ls",
        "pwd",
        "cd",
        "cat",
        "mkdir",
        "touch",
        "rm",
        "clear",
        "whoami",
        "date",
        "echo",
        "history",
        "tree",
        // Crypto commands
        "hash",
        "encrypt",
        "decrypt",
        "keygen",
        "sign",
        "hmac",
        "password",
        "blockchain",
        "jwt",
        "stego",
        "random",
        "crypto-help",
      ]
      const matches = commands.filter((cmd) => cmd.startsWith(currentWord))

      if (matches.length === 1) {
        const completion = matches[0].slice(currentWord.length)
        this.currentLine += completion + " "
        this.cursorPosition = this.currentLine.length
        this.refreshLine()
      }
    }
  }

  private handlePrintableChar(char: string) {
    this.currentLine =
      this.currentLine.slice(0, this.cursorPosition) + char + this.currentLine.slice(this.cursorPosition)
    this.cursorPosition++
    this.refreshLine()
  }

  private handleHistoryUp() {
    const history = this.store.commandHistory
    let index = this.store.historyIndex

    if (index === -1) {
      index = history.length - 1
    } else if (index > 0) {
      index--
    }

    if (index >= 0 && history[index]) {
      this.store.setHistoryIndex(index)
      this.currentLine = history[index]
      this.cursorPosition = this.currentLine.length
      this.refreshLine()
    }
  }

  private handleHistoryDown() {
    const history = this.store.commandHistory
    let index = this.store.historyIndex

    if (index < history.length - 1) {
      index++
      this.store.setHistoryIndex(index)
      this.currentLine = history[index]
      this.cursorPosition = this.currentLine.length
      this.refreshLine()
    } else {
      this.store.setHistoryIndex(-1)
      this.currentLine = ""
      this.cursorPosition = 0
      this.refreshLine()
    }
  }

  private refreshLine() {
    // Clear current line and rewrite
    this.terminal.write("\r\x1b[K")
    this.showPrompt()
    this.terminal.write(this.currentLine)

    // Position cursor
    const targetPos = this.getPromptLength() + this.cursorPosition
    const currentPos = this.getPromptLength() + this.currentLine.length
    const diff = currentPos - targetPos

    if (diff > 0) {
      this.terminal.write(`\x1b[${diff}D`)
    }
  }

  private getPromptLength(): number {
    const user = this.store.user
    const dir = this.store.currentDirectory.replace("/home/user", "~")
    return `${user.name}@${user.host}:${dir}$ `.length
  }

  public showPrompt() {
    const user = this.store.user
    const dir = this.store.currentDirectory.replace("/home/user", "~")
    this.terminal.write(`\x1b[32m${user.name}@${user.host}\x1b[0m:\x1b[34m${dir}\x1b[0m$ `)
  }

  private async executeCommand(command: string) {
    const [cmd, ...args] = command.split(" ")

    // Check if it's a crypto command
    const cryptoCommands = [
      "hash",
      "encrypt",
      "decrypt",
      "keygen",
      "sign",
      "hmac",
      "password",
      "blockchain",
      "jwt",
      "stego",
      "steganography",
      "random",
      "crypto-help",
    ]

    if (cryptoCommands.includes(cmd.toLowerCase())) {
      await this.cryptoCommands.executeCommand(cmd, args)
      return
    }

    switch (cmd.toLowerCase()) {
      case "help":
        this.showHelp()
        break
      case "clear":
        this.terminal.clear()
        break
      case "ls":
        this.listDirectory(args)
        break
      case "pwd":
        this.printWorkingDirectory()
        break
      case "cd":
        this.changeDirectory(args[0])
        break
      case "cat":
        this.showFileContent(args[0])
        break
      case "whoami":
        this.showUserInfo()
        break
      case "date":
        this.showDate()
        break
      case "echo":
        this.echo(args.join(" "))
        break
      case "history":
        this.showHistory()
        break
      case "tree":
        this.showTree()
        break
      case "mkdir":
        this.makeDirectory(args[0])
        break
      case "touch":
        this.createFile(args[0])
        break
      case "json":
        this.outputJson(args)
        break
      default:
        this.terminal.writeln(`\x1b[31mCommand not found: ${cmd}\x1b[0m`)
        this.terminal.writeln(`Type 'help' or 'crypto-help' to see available commands.`)
    }
  }

  private showHelp() {
    const commands = [
      { cmd: "help", desc: "Show this help message" },
      { cmd: "crypto-help", desc: "Show cryptography commands" },
      { cmd: "clear", desc: "Clear the terminal screen" },
      { cmd: "ls [options]", desc: "List directory contents" },
      { cmd: "pwd", desc: "Print working directory" },
      { cmd: "cd <directory>", desc: "Change directory" },
      { cmd: "cat <file>", desc: "Display file contents" },
      { cmd: "whoami", desc: "Display current user information" },
      { cmd: "date", desc: "Display current date and time" },
      { cmd: "echo <text>", desc: "Display text" },
      { cmd: "history", desc: "Show command history" },
      { cmd: "tree", desc: "Display directory tree" },
      { cmd: "mkdir <name>", desc: "Create directory" },
      { cmd: "touch <name>", desc: "Create file" },
      { cmd: "json <data>", desc: "Output formatted JSON" },
    ]

    this.terminal.writeln("\x1b[33m╔══════════════════════════════════════════════════════════════╗\x1b[0m")
    this.terminal.writeln("\x1b[33m║                    Available Commands                        ║\x1b[0m")
    this.terminal.writeln("\x1b[33m╚══════════════════════════════════════════════════════════════╝\x1b[0m")
    this.terminal.writeln("")

    commands.forEach(({ cmd, desc }) => {
      this.terminal.writeln(`  \x1b[36m${cmd.padEnd(20)}\x1b[0m ${desc}`)
    })

    this.terminal.writeln("")
    this.terminal.writeln("\x1b[31m🔐 NEW: Advanced Cryptography Suite Available!\x1b[0m")
    this.terminal.writeln("  Type '\x1b[33mcrypto-help\x1b[0m' to see 12+ crypto commands")
    this.terminal.writeln("  Features: AES encryption, RSA keys, blockchain, JWT, steganography")
    this.terminal.writeln("")
    this.terminal.writeln("\x1b[33mNavigation:\x1b[0m")
    this.terminal.writeln("  ↑/↓ arrows    Navigate command history")
    this.terminal.writeln("  Tab           Auto-complete commands")
    this.terminal.writeln("  Ctrl+C        Interrupt current command")
    this.terminal.writeln("")
  }

  private listDirectory(args: string[]) {
    const contents = this.store.getDirectoryContents(this.store.currentDirectory)
    const showJson = args.includes("--json")
    const showLong = args.includes("-l")

    if (showJson) {
      const jsonOutput = {
        directory: this.store.currentDirectory,
        contents: contents.map((item) => ({
          name: item.name,
          type: item.type,
          size: item.size,
          permissions: item.permissions,
          modified: item.modified,
        })),
      }
      this.terminal.writeln(JSON.stringify(jsonOutput, null, 2))
      return
    }

    if (showLong) {
      contents.forEach((item) => {
        const size = item.size ? item.size.toString().padStart(8) : "     -  "
        const color = item.type === "directory" ? "\x1b[34m" : "\x1b[0m"
        this.terminal.writeln(`${item.permissions} ${size} ${item.modified} ${color}${item.name}\x1b[0m`)
      })
    } else {
      const items = contents.map((item) => {
        const color = item.type === "directory" ? "\x1b[34m" : "\x1b[0m"
        return `${color}${item.name}\x1b[0m`
      })
      this.terminal.writeln(items.join("  "))
    }
  }

  private printWorkingDirectory() {
    const jsonOutput = {
      current_directory: this.store.currentDirectory,
      user: this.store.user.name,
      host: this.store.user.host,
    }
    this.terminal.writeln(JSON.stringify(jsonOutput, null, 2))
  }

  private changeDirectory(path: string) {
    if (!path) {
      this.store.setCurrentDirectory("/home/user")
      return
    }

    let newPath: string
    if (path.startsWith("/")) {
      newPath = path
    } else if (path === "..") {
      const parts = this.store.currentDirectory.split("/").filter((p) => p)
      parts.pop()
      newPath = "/" + parts.join("/")
      if (newPath === "/") newPath = "/"
    } else if (path === "~") {
      newPath = "/home/user"
    } else {
      newPath = this.store.currentDirectory === "/" ? `/${path}` : `${this.store.currentDirectory}/${path}`
    }

    // Check if directory exists
    if (this.store.fileSystem[newPath] !== undefined) {
      this.store.setCurrentDirectory(newPath)
    } else {
      this.terminal.writeln(`\x1b[31mcd: ${path}: No such file or directory\x1b[0m`)
    }
  }

  private showFileContent(filename: string) {
    if (!filename) {
      this.terminal.writeln("\x1b[31mcat: missing file operand\x1b[0m")
      return
    }

    const contents = this.store.getDirectoryContents(this.store.currentDirectory)
    const file = contents.find((item) => item.name === filename && item.type === "file")

    if (!file) {
      this.terminal.writeln(`\x1b[31mcat: ${filename}: No such file or directory\x1b[0m`)
      return
    }

    if (file.content) {
      this.terminal.writeln(file.content)
    } else {
      this.terminal.writeln("\x1b[33m(empty file)\x1b[0m")
    }
  }

  private showUserInfo() {
    const userInfo = {
      username: this.store.user.name,
      hostname: this.store.user.host,
      shell: this.store.user.shell,
      current_directory: this.store.currentDirectory,
      terminal: "TerminalMe(CLI) v2.0 - Crypto Edition",
      crypto_engine: "Advanced Cryptography Suite Enabled",
    }
    this.terminal.writeln(JSON.stringify(userInfo, null, 2))
  }

  private showDate() {
    const now = new Date()
    const dateInfo = {
      timestamp: now.toISOString(),
      formatted: now.toLocaleString(),
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      unix_timestamp: Math.floor(now.getTime() / 1000),
    }
    this.terminal.writeln(JSON.stringify(dateInfo, null, 2))
  }

  private echo(text: string) {
    this.terminal.writeln(text)
  }

  private showHistory() {
    const history = this.store.commandHistory
    const historyInfo = {
      total_commands: history.length,
      commands: history.map((cmd, index) => ({
        index: index + 1,
        command: cmd,
      })),
    }
    this.terminal.writeln(JSON.stringify(historyInfo, null, 2))
  }

  private showTree() {
    const buildTree = (path: string, prefix = "", isLast = true): string[] => {
      const contents = this.store.getDirectoryContents(path)
      const lines: string[] = []

      contents.forEach((item, index) => {
        const isLastItem = index === contents.length - 1
        const connector = isLastItem ? "└── " : "├── "
        const color = item.type === "directory" ? "\x1b[34m" : "\x1b[0m"

        lines.push(`${prefix}${connector}${color}${item.name}\x1b[0m`)

        if (item.type === "directory") {
          const childPath = path === "/" ? `/${item.name}` : `${path}/${item.name}`
          const childPrefix = prefix + (isLastItem ? "    " : "│   ")
          lines.push(...buildTree(childPath, childPrefix, isLastItem))
        }
      })

      return lines
    }

    this.terminal.writeln(`\x1b[34m${this.store.currentDirectory}\x1b[0m`)
    const tree = buildTree(this.store.currentDirectory)
    tree.forEach((line) => this.terminal.writeln(line))
  }

  private makeDirectory(name: string) {
    if (!name) {
      this.terminal.writeln("\x1b[31mmkdir: missing operand\x1b[0m")
      return
    }

    this.store.createDirectory(this.store.currentDirectory, name)
    this.terminal.writeln(`Directory '${name}' created successfully`)
  }

  private createFile(name: string) {
    if (!name) {
      this.terminal.writeln("\x1b[31mtouch: missing file operand\x1b[0m")
      return
    }

    this.store.createFile(this.store.currentDirectory, name, "")
    this.terminal.writeln(`File '${name}' created successfully`)
  }

  private outputJson(args: string[]) {
    if (args.length === 0) {
      this.terminal.writeln("\x1b[31mjson: missing data operand\x1b[0m")
      return
    }

    try {
      const data = args.join(" ")
      const parsed = JSON.parse(data)
      this.terminal.writeln(JSON.stringify(parsed, null, 2))
    } catch (error) {
      // If not valid JSON, create a simple object
      const result = {
        input: args.join(" "),
        timestamp: new Date().toISOString(),
        type: "text_input",
      }
      this.terminal.writeln(JSON.stringify(result, null, 2))
    }
  }
}
