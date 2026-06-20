package app

// TemplateListItem is the lightweight catalog entry (no doc_md / defaults / fields).
type TemplateListItem struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Icon        string `json:"icon,omitempty"`
	Category    string `json:"category"`
	Protocol    string `json:"protocol"`
	Description string `json:"description,omitempty"`
}

// ToTemplateListItems projects full templates down to catalog entries.
func ToTemplateListItems(ts []Template) []TemplateListItem {
	out := make([]TemplateListItem, len(ts))
	for i, tpl := range ts {
		out[i] = TemplateListItem{
			Key:         tpl.Key,
			Name:        tpl.Name,
			Icon:        tpl.Icon,
			Category:    tpl.Category,
			Protocol:    tpl.Protocol,
			Description: tpl.Description,
		}
	}
	return out
}
