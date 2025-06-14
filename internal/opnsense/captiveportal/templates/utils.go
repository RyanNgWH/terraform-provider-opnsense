package templates

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	templatesController = "templates"

	resourceName = "captive portal template"
)

type captivePortalTemplate struct {
	Template       string
	TemplateBase64 string
	TemplateSha512 string
	Name           string
	FileId         string
}

// createCaptivePortalTemplate creates a captive portal template object based on the specified plan.
func createCaptivePortalTemplate(ctx context.Context, plan captivePortalTemplatesResourceModel) (captivePortalTemplate, diag.Diagnostics) {
	var diagnostics diag.Diagnostics

	// Create captive portal template from plan
	tflog.Debug(ctx, fmt.Sprintf("Creating %s object from plan", resourceName), map[string]any{"plan": plan})

	path, err := filepath.Abs(plan.Template.ValueString())
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Failed to get template absolute file path - %s", err))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		diagnostics.AddError(fmt.Sprintf("Create %s object error", resourceName), fmt.Sprintf("Failed to read template file - %s", err))
	}
	base64Template := base64.StdEncoding.EncodeToString(content)

	sha512Template := hex.EncodeToString(sha512.New().Sum(content))

	captivePortalTemplate := captivePortalTemplate{
		Template:       plan.Template.ValueString(),
		TemplateBase64: base64Template,
		TemplateSha512: sha512Template,
		Name:           plan.Name.ValueString(),
	}

	tflog.Debug(ctx, fmt.Sprintf("Successfully created %s object from plan", resourceName), map[string]any{"success": true})

	return captivePortalTemplate, diagnostics
}
