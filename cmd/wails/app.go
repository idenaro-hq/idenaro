package main

import (
	"context"

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails application struct. All exported methods become callable
// from the frontend via window['go']['main']['App'][methodName].
type App struct {
	ctx         context.Context
	cancel      context.CancelFunc
	lastSkipTLS bool // remembered so Export uses same TLS setting as the scan
}

func newApp() *App { return &App{} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.fitWindowToScreen()
}

func (a *App) shutdown(_ context.Context) {
	if a.cancel != nil {
		a.cancel()
	}
}

const windowScaleFactor = 0.87

// fitWindowToScreen resizes the window to 87% of the primary screen's logical
// size and centers it, so the UI fills most of the monitor regardless of resolution.
func (a *App) fitWindowToScreen() {
	screens, err := wailsruntime.ScreenGetAll(a.ctx)
	if err != nil || len(screens) == 0 {
		return
	}

	screen := screens[0]
	for _, s := range screens {
		if s.IsPrimary {
			screen = s
			break
		}
	}

	w := int(float64(screen.Size.Width) * windowScaleFactor)
	h := int(float64(screen.Size.Height) * windowScaleFactor)

	const (
		minWidth  = 1242
		minHeight = 828
	)
	if w < minWidth {
		w = minWidth
	}
	if h < minHeight {
		h = minHeight
	}

	wailsruntime.WindowSetSize(a.ctx, w, h)
	wailsruntime.WindowCenter(a.ctx)
}
