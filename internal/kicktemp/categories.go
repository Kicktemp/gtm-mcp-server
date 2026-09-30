package kicktemp

// Category classifies what a tool can do to a GTM account.
type Category string

const (
	CategoryRead    Category = "read"
	CategoryWrite   Category = "write"
	CategoryDelete  Category = "delete"
	CategoryPublish Category = "publish"
	CategoryAdmin   Category = "admin"
)

// Scope tells which arguments identify the GTM target of a tool.
type Scope int

const (
	// ScopeContainer: accountId + containerId identify the target.
	ScopeContainer Scope = iota
	// ScopeAccount: only accountId identifies the target.
	ScopeAccount
	// ScopeNone: the tool has no GTM target.
	ScopeNone
	// ScopeLookup: the tool resolves a container by public ID or destination ID.
	ScopeLookup
)

// ToolInfo is the policy metadata of one MCP tool.
type ToolInfo struct {
	Category Category
	Scope    Scope
}

// unknownTool is what an unclassified tool is treated as: the most restricted
// category, so a tool added by an upstream release is disabled until reviewed.
var unknownTool = ToolInfo{Category: CategoryAdmin, Scope: ScopeContainer}

// Lookup returns the policy metadata for a tool name. Unknown tools are
// classified as admin (fail-closed).
func Lookup(name string) (ToolInfo, bool) {
	info, ok := tools[name]
	if !ok {
		return unknownTool, false
	}
	return info, true
}

func toolsOf(cat Category, scope Scope, names ...string) map[string]ToolInfo {
	m := make(map[string]ToolInfo, len(names))
	for _, n := range names {
		m[n] = ToolInfo{Category: cat, Scope: scope}
	}
	return m
}

var tools = merge(
	toolsOf(CategoryRead, ScopeNone,
		"list_accounts", "get_tag_templates", "get_trigger_templates", "ping", "auth_status"),
	toolsOf(CategoryRead, ScopeLookup, "lookup_container"),
	toolsOf(CategoryRead, ScopeAccount, "list_containers"),
	toolsOf(CategoryRead, ScopeContainer,
		"get_container_snippet",
		"list_workspaces", "get_workspace", "quick_preview_workspace", "get_workspace_status",
		"list_versions", "get_latest_version_header", "get_version", "get_live_version",
		"list_tags", "get_tag", "list_triggers", "get_trigger", "list_variables", "get_variable",
		"list_folders", "get_folder", "get_folder_entities",
		"list_zones", "get_zone", "list_environments", "get_environment",
		"list_destinations", "get_destination",
		"list_google_tag_configs", "get_google_tag_config",
		"list_built_in_variables", "list_templates", "get_template",
		"list_clients", "get_client", "list_transformations", "get_transformation"),

	toolsOf(CategoryWrite, ScopeContainer,
		"create_workspace", "update_workspace", "sync_workspace",
		"create_version", "update_version", "undelete_version",
		"create_tag", "update_tag", "create_trigger", "update_trigger",
		"create_variable", "update_variable",
		"create_folder", "update_folder", "move_entities_to_folder",
		"create_zone", "update_zone",
		"create_google_tag_config", "update_google_tag_config",
		"enable_built_in_variables",
		"create_template", "update_template", "import_gallery_template",
		"create_client", "update_client", "create_transformation", "update_transformation"),

	// bulk_update_workspace and resolve_workspace_conflict take free-form JSON
	// and can remove entities, so they count as delete.
	toolsOf(CategoryDelete, ScopeContainer,
		"delete_workspace", "delete_version", "delete_tag", "delete_trigger", "delete_variable",
		"delete_folder", "revert_folder", "revert_workspace_entity",
		"bulk_update_workspace", "resolve_workspace_conflict",
		"delete_zone", "delete_google_tag_config", "disable_built_in_variables",
		"delete_template", "delete_client", "delete_transformation"),

	toolsOf(CategoryPublish, ScopeContainer, "publish_version", "set_latest_version"),

	toolsOf(CategoryAdmin, ScopeAccount, "update_account", "create_container"),
	toolsOf(CategoryAdmin, ScopeContainer,
		"update_container", "delete_container", "combine_containers", "move_tag_id",
		"create_environment", "update_environment", "reauthorize_environment", "delete_environment",
		"link_destination"),
)

func merge(parts ...map[string]ToolInfo) map[string]ToolInfo {
	out := map[string]ToolInfo{}
	for _, p := range parts {
		for k, v := range p {
			if _, dup := out[k]; dup {
				panic("kicktemp: duplicate tool classification: " + k)
			}
			out[k] = v
		}
	}
	return out
}

// Names returns every classified tool name.
func Names() []string {
	names := make([]string, 0, len(tools))
	for n := range tools {
		names = append(names, n)
	}
	return names
}
