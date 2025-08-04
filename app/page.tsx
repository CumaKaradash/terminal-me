"use client"

import { useEffect, useRef } from "react"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import { WebLinksAddon } from "@xterm/addon-web-links"
import "@xterm/xterm/css/xterm.css"
import { useTerminalStore } from "@/lib/terminal-store"
import { CommandProcessor } from "@/lib/command-processor"

export default function TerminalPage() {
  const terminalRef = useRef<HTMLDivElement>(null)
  const terminal = useRef<Terminal | null>(null)
  const fitAddon = useRef<FitAddon | null>(null)
  const commandProcessor = useRef<CommandProcessor | null>(null)

  const { currentDirectory, commandHistory, addToHistory, currentInput, setCurrentInput } = useTerminalStore()

  useEffect(() => {
    if (!terminalRef.current) return

    // Initialize terminal
    terminal.current = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "JetBrains Mono, Consolas, Monaco, monospace",
      theme: {
        background: "#0d1117",
        foreground: "#c9d1d9",
        cursor: "#58a6ff",
        selection: "#264f78",
        black: "#484f58",
        red: "#ff7b72",
        green: "#7ee787",
        yellow: "#d29922",
        blue: "#58a6ff",
        magenta: "#bc8cff",
        cyan: "#39c5cf",
        white: "#b1bac4",
        brightBlack: "#6e7681",
        brightRed: "#ffa198",
        brightGreen: "#56d364",
        brightYellow: "#e3b341",
        brightBlue: "#79c0ff",
        brightMagenta: "#d2a8ff",
        brightCyan: "#56d4dd",
        brightWhite: "#f0f6fc",
      },
    })

    // Initialize addons
    fitAddon.current = new FitAddon()
    const webLinksAddon = new WebLinksAddon()

    terminal.current.loadAddon(fitAddon.current)
    terminal.current.loadAddon(webLinksAddon)

    // Initialize command processor
    commandProcessor.current = new CommandProcessor(terminal.current)

    // Open terminal
    terminal.current.open(terminalRef.current)
    fitAddon.current.fit()

    // Welcome message
    terminal.current.writeln("\x1b[36m╔══════════════════════════════════════════════════════════════╗\x1b[0m")
    terminal.current.writeln("\x1b[36m║                     TerminalMe(CLI) v1.0                     ║\x1b[0m")
    terminal.current.writeln("\x1b[36m║              Web-based Terminal Simulation                   ║\x1b[0m")
    terminal.current.writeln("\x1b[36m╚══════════════════════════════════════════════════════════════╝\x1b[0m")
    terminal.current.writeln("")
    terminal.current.writeln('\x1b[33mWelcome to TerminalMe! Type "help" to see available commands.\x1b[0m')
    terminal.current.writeln("")

    // Show initial prompt
    commandProcessor.current.showPrompt()

    // Handle resize
    const handleResize = () => {
      if (fitAddon.current) {
        fitAddon.current.fit()
      }
    }

    window.addEventListener("resize", handleResize)

    return () => {
      window.removeEventListener("resize", handleResize)
      if (terminal.current) {
        terminal.current.dispose()
      }
    }
  }, [])

  return (
    <div className="min-h-screen bg-[#0d1117] p-4">
      <div className="max-w-6xl mx-auto">
        <div className="bg-[#161b22] rounded-lg border border-[#30363d] overflow-hidden shadow-2xl">
          {/* Terminal Header */}
          <div className="flex items-center justify-between px-4 py-2 bg-[#21262d] border-b border-[#30363d]">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-[#ff5f56]"></div>
              <div className="w-3 h-3 rounded-full bg-[#ffbd2e]"></div>
              <div className="w-3 h-3 rounded-full bg-[#27ca3f]"></div>
            </div>
            <div className="text-[#8b949e] text-sm font-mono">TerminalMe(CLI) - {currentDirectory}</div>
            <div className="w-16"></div>
          </div>

          {/* Terminal Content */}
          <div
            ref={terminalRef}
            className="h-[600px] p-4"
            style={{
              background: "#0d1117",
              fontFamily: "JetBrains Mono, Consolas, Monaco, monospace",
            }}
          />
        </div>

        {/* Info Panel */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-[#161b22] rounded-lg border border-[#30363d] p-4">
            <h3 className="text-[#f0f6fc] font-semibold mb-2">Features</h3>
            <ul className="text-[#8b949e] text-sm space-y-1">
              <li>• Custom command system</li>
              <li>• JSON output formatting</li>
              <li>• Command history (↑/↓)</li>
              <li>• Tab completion</li>
              <li>• File system simulation</li>
            </ul>
          </div>

          <div className="bg-[#161b22] rounded-lg border border-[#30363d] p-4">
            <h3 className="text-[#f0f6fc] font-semibold mb-2">Quick Commands</h3>
            <ul className="text-[#8b949e] text-sm space-y-1">
              <li>
                • <code className="text-[#79c0ff]">help</code> - Show all commands
              </li>
              <li>
                • <code className="text-[#79c0ff]">ls</code> - List directory contents
              </li>
              <li>
                • <code className="text-[#79c0ff]">pwd</code> - Show current directory
              </li>
              <li>
                • <code className="text-[#79c0ff]">whoami</code> - Show user info
              </li>
              <li>
                • <code className="text-[#79c0ff]">clear</code> - Clear terminal
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
