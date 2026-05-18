package mcpconfig

// Client identifies the AI agent whose MCP config Veil is reading.
type Client string

const (
	ClaudeDesktop Client = "claude-desktop"
	ClaudeCode    Client = "claude-code"
	Cursor        Client = "cursor"
)

// Scope distinguishes user-global configs (one per user account) from
// project-local configs (inside the project tree).
type Scope string

const (
	UserScope    Scope = "user"
	ProjectScope Scope = "project"
)

// DiscoveredConfig describes one MCP config the init flow should process.
type DiscoveredConfig struct {
	Path   string
	Client Client
	Scope  Scope
}

// userLocation describes one user-global MCP config location. The subpath
// resolver receives goos so platform-specific paths (Claude Desktop on
// macOS vs Linux) stay encapsulated.
type userLocation struct {
	Client  Client
	Scope   Scope
	subpath func(goos string) []string
}

// userLocations returns the table of probed user-global MCP config locations.
// Order is meaningful only insofar as it controls the order of summary output.
func userLocations() []userLocation {
	return []userLocation{
		{
			Client: ClaudeDesktop,
			Scope:  UserScope,
			subpath: func(goos string) []string {
				switch goos {
				case "darwin":
					return []string{"Library", "Application Support", "Claude", "claude_desktop_config.json"}
				case "linux":
					return []string{".config", "Claude", "claude_desktop_config.json"}
				default:
					return nil
				}
			},
		},
		{
			Client: ClaudeCode,
			Scope:  UserScope,
			subpath: func(goos string) []string {
				return []string{".claude.json"}
			},
		},
		{
			Client: Cursor,
			Scope:  UserScope,
			subpath: func(goos string) []string {
				return []string{".cursor", "mcp.json"}
			},
		},
	}
}

// ProjectFilename describes a project-relative MCP config path the .env
// walker also surfaces. Path is a list of path components to be joined under
// the project root.
type ProjectFilename struct {
	Client Client
	Path   []string
}

// ProjectFilenames returns the set of project-relative MCP config paths the
// init walker should match. The walker emits hits for files at these paths
// anywhere in the project tree (not only at root) — a monorepo with
// per-package agents is realistic.
func ProjectFilenames() []ProjectFilename {
	return []ProjectFilename{
		{Client: ClaudeCode, Path: []string{".mcp.json"}},
		{Client: Cursor, Path: []string{".cursor", "mcp.json"}},
	}
}
