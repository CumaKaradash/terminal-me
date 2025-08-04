"use client"

import dynamic from "next/dynamic"
import { Suspense } from "react"
import "@xterm/xterm/css/xterm.css"

// Dynamically import the terminal component with no SSR
const TerminalComponent = dynamic(() => import("@/components/terminal-component"), {
  ssr: false,
  loading: () => (
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
            <div className="text-[#8b949e] text-sm font-mono">TerminalMe(CLI) - Loading...</div>
            <div className="w-16"></div>
          </div>

          {/* Loading Content */}
          <div className="h-[600px] p-4 bg-[#0d1117] flex items-center justify-center">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#58a6ff] mx-auto mb-4"></div>
              <div className="text-[#c9d1d9] font-mono">Initializing Terminal...</div>
              <div className="text-[#8b949e] text-sm mt-2">Loading XTerm.js and Crypto Engine</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  ),
})

export default function TerminalPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <TerminalComponent />
    </Suspense>
  )
}
