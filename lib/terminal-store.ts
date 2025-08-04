import { create } from "zustand"

interface FileSystemItem {
  name: string
  type: "file" | "directory"
  size?: number
  modified: string
  permissions: string
  content?: string
}

interface TerminalState {
  currentDirectory: string
  commandHistory: string[]
  historyIndex: number
  currentInput: string
  fileSystem: Record<string, FileSystemItem[]>
  user: {
    name: string
    host: string
    shell: string
  }

  // Actions
  setCurrentDirectory: (dir: string) => void
  addToHistory: (command: string) => void
  setHistoryIndex: (index: number) => void
  setCurrentInput: (input: string) => void
  getDirectoryContents: (path: string) => FileSystemItem[]
  createFile: (path: string, name: string, content?: string) => void
  createDirectory: (path: string, name: string) => void
}

export const useTerminalStore = create<TerminalState>((set, get) => ({
  currentDirectory: "/home/user",
  commandHistory: [],
  historyIndex: -1,
  currentInput: "",
  user: {
    name: "user",
    host: "terminalmecli",
    shell: "/bin/bash",
  },

  fileSystem: {
    "/": [
      { name: "home", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
      { name: "usr", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
      { name: "var", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
      { name: "etc", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
    ],
    "/home": [{ name: "user", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" }],
    "/home/user": [
      { name: "documents", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
      { name: "projects", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
      {
        name: "readme.txt",
        type: "file",
        size: 256,
        modified: "2024-01-15 10:30",
        permissions: "-rw-r--r--",
        content: "Welcome to TerminalMe CLI!",
      },
      {
        name: "config.json",
        type: "file",
        size: 512,
        modified: "2024-01-15 10:30",
        permissions: "-rw-r--r--",
        content: '{"theme": "dark", "shell": "bash"}',
      },
    ],
    "/home/user/documents": [
      {
        name: "notes.md",
        type: "file",
        size: 1024,
        modified: "2024-01-15 10:30",
        permissions: "-rw-r--r--",
        content: "# My Notes\n\nThis is a markdown file.",
      },
      {
        name: "todo.txt",
        type: "file",
        size: 128,
        modified: "2024-01-15 10:30",
        permissions: "-rw-r--r--",
        content: "- Learn React\n- Build terminal app\n- Deploy to production",
      },
    ],
    "/home/user/projects": [
      { name: "webapp", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
      { name: "scripts", type: "directory", modified: "2024-01-15 10:30", permissions: "drwxr-xr-x" },
    ],
  },

  setCurrentDirectory: (dir) => set({ currentDirectory: dir }),

  addToHistory: (command) =>
    set((state) => ({
      commandHistory: [...state.commandHistory, command],
      historyIndex: -1,
    })),

  setHistoryIndex: (index) => set({ historyIndex: index }),
  setCurrentInput: (input) => set({ currentInput: input }),

  getDirectoryContents: (path) => {
    const state = get()
    return state.fileSystem[path] || []
  },

  createFile: (path, name, content = "") =>
    set((state) => ({
      fileSystem: {
        ...state.fileSystem,
        [path]: [
          ...(state.fileSystem[path] || []),
          {
            name,
            type: "file",
            size: content.length,
            modified: new Date().toISOString().slice(0, 16).replace("T", " "),
            permissions: "-rw-r--r--",
            content,
          },
        ],
      },
    })),

  createDirectory: (path, name) =>
    set((state) => ({
      fileSystem: {
        ...state.fileSystem,
        [path]: [
          ...(state.fileSystem[path] || []),
          {
            name,
            type: "directory",
            modified: new Date().toISOString().slice(0, 16).replace("T", " "),
            permissions: "drwxr-xr-x",
          },
        ],
        [`${path}/${name}`]: [],
      },
    })),
}))
