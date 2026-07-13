package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/imkerbos/mxid/internal/domain/upload"
	"github.com/imkerbos/mxid/pkg/authz"
	"github.com/imkerbos/mxid/pkg/response"
	"github.com/imkerbos/mxid/pkg/snowflake"
)

// errIconRejected wraps the operator-fixable saveIcon failures (too large,
// unsupported type). The handler 400s on it and routes every OTHER saveIcon
// error (a wrapped io/DB failure) to a logged 500 rather than echoing the infra
// error text back to the client.
var errIconRejected = errors.New("icon rejected")

// Uploaded assets live in the database (see internal/domain/upload), NOT on
// local disk — so the backend keeps no local file state. The serve path reads
// straight from the row and strong-caches it.

const (
	// 2 MB ceiling. App icons / brand logos are small; this comfortably covers a
	// high-res PNG/JPG logo while still rejecting accidental full-size photos.
	// nginx client_max_body_size (50m) is well above this.
	maxIconBytes = 2 * 1024 * 1024

	iconCategory = "app-icon"
	// iconPrefix is the public URL prefix. Kept identical to the legacy on-disk
	// layout so existing app.icon / branding.logo_url values keep their shape.
	iconPrefix = "/static/app-icons/"
)

// allowedIconMime caps the accepted formats. Raster only — SVG is deliberately
// excluded: it can embed <script>, and icons are served same-origin and
// unauthenticated, so a scripted SVG would be stored XSS. Rejecting unknown
// types also keeps users from uploading PDFs or HEIC that don't render.
var allowedIconMime = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/webp": ".webp",
	"image/gif":  ".gif",
}

// RegisterUpload wires the icon upload endpoint and the DB-backed static serve.
// Assets live in the database, so there are no local files: no PVC under k8s,
// icons survive restarts under docker, and every replica serves identical bytes.
func RegisterUpload(r *gin.Engine, consoleGroup *gin.RouterGroup, idGen *snowflake.Generator, repo upload.Repository) error {
	// Serve: GET /static/app-icons/<id>.<ext>. The <ext> is cosmetic (the real
	// content-type comes from the row); only the id is parsed. Root-level + no
	// auth: login pages fetch icons via <img> with no cookie.
	r.GET(iconPrefix+":name", func(c *gin.Context) {
		id := parseIconID(c.Param("name"))
		if id == 0 {
			c.Status(http.StatusNotFound)
			return
		}
		// Immutable: a new upload always mints a new id, so a given URL's bytes
		// never change. Cache hard (1 year, immutable) and honour revalidation
		// before touching the DB.
		etag := `"` + strconv.FormatInt(id, 10) + `"`
		if c.GetHeader("If-None-Match") == etag {
			c.Status(http.StatusNotModified)
			return
		}
		u, err := repo.Get(c.Request.Context(), id)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Header("Cache-Control", "public, max-age=31536000, immutable")
		c.Header("ETag", etag)
		// Defense-in-depth for the unauthenticated same-origin asset serve:
		// never let the browser sniff a different type, and sandbox/deny any
		// active content if the URL is navigated to directly.
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Content-Security-Policy", "default-src 'none'; sandbox")
		c.Data(http.StatusOK, u.Mime, u.Data)
	})

	// Icon upload is part of app authoring — used by both the create and edit
	// forms (no app id exists yet at create time), so allow either app.create
	// or app.update. RequireAny does the RBAC check; the matching entry in
	// consoleProtectedRoutes registers it with the deny-by-default gateway.
	consoleGroup.POST("/upload/app-icon", authz.RequireAny([]string{"app.create", "app.update"}, nil), func(c *gin.Context) {
		f, header, err := c.Request.FormFile("file")
		if err != nil {
			response.BadRequest(c, 40001, "file field required")
			return
		}
		defer f.Close()

		url, err := saveIcon(c.Request.Context(), f, header, repo, idGen)
		if err != nil {
			if errors.Is(err, errIconRejected) {
				response.BadRequest(c, 40002, err.Error())
				return
			}
			response.InternalError(c, "failed to save icon", err)
			return
		}
		response.OK(c, gin.H{"url": url})
	})

	return nil
}

// parseIconID extracts the Snowflake id from "<id>.<ext>" (or a bare "<id>").
// Returns 0 on anything unparseable.
func parseIconID(name string) int64 {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	id, err := strconv.ParseInt(name, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// saveIcon validates and persists an uploaded icon into the DB. Returns the
// public URL the caller stores in app.icon. Content-type is taken from the
// multipart header (caller-supplied — fine here since the endpoint is the
// trusted admin console, not anonymous).
func saveIcon(ctx context.Context, src multipart.File, header *multipart.FileHeader, repo upload.Repository, idGen *snowflake.Generator) (string, error) {
	if header.Size > maxIconBytes {
		return "", fmt.Errorf("%w: file too large: %d bytes (max %d)", errIconRejected, header.Size, maxIconBytes)
	}

	mime := strings.ToLower(header.Header.Get("Content-Type"))
	// Some browsers attach charset to svg+xml — trim it.
	if i := strings.Index(mime, ";"); i > 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	ext, ok := allowedIconMime[mime]
	if !ok {
		return "", fmt.Errorf("%w: unsupported content-type: %s", errIconRejected, mime)
	}

	// Read into memory with a hard cap (+1 to detect a lying Content-Length that
	// claims <= max but streams more).
	data, err := io.ReadAll(io.LimitReader(src, maxIconBytes+1))
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	if len(data) > maxIconBytes {
		return "", fmt.Errorf("%w: file too large (max %d bytes)", errIconRejected, maxIconBytes)
	}

	id := idGen.Generate()
	if err := repo.Save(ctx, &upload.Upload{
		ID:       id,
		Category: iconCategory,
		Mime:     mime,
		Ext:      ext,
		Size:     len(data),
		Data:     data,
	}); err != nil {
		return "", fmt.Errorf("save upload: %w", err)
	}

	return fmt.Sprintf("%s%d%s", iconPrefix, id, ext), nil
}
