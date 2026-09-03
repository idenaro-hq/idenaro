package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

// frontend embeds the compiled React app from the frontend/dist directory.
// `wails build` populates this directory automatically.
//
//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

func main() {
	app := newApp()

	err := wails.Run(&options.App{
		Title:     "Idenaro",
		Width:     1656,
		Height:    1076,
		MinWidth:  1242,
		MinHeight: 828,

		AssetServer: &assetserver.Options{
			Assets: assets,
		},

		// Use a custom in-app title bar so the window chrome matches the
		// application theme on every platform.
		Frameless: true,

		// Dark background matches the slate-900 UI theme so there is no white
		// flash during initial load.
		BackgroundColour: &options.RGBA{R: 12, G: 11, B: 18, A: 255},

		OnStartup:  app.startup,
		OnShutdown: app.shutdown,

		// Bind the App struct - all exported methods become callable from JS
		// as window.go.MethodName(...).
		Bind: []interface{}{app},

		// Platform-specific window chrome options.
		Mac: &mac.Options{
			TitleBar: &mac.TitleBar{
				TitlebarAppearsTransparent: true,
				HideTitle:                  true,
				HideTitleBar:               true,
				FullSizeContent:            false,
				UseToolbar:                 false,
			},
			Appearance:           mac.DefaultAppearance,
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},

		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 false,
			IsZoomControlEnabled:              false,
			DisableFramelessWindowDecorations: true,
		},

		Linux: &linux.Options{
			WindowIsTranslucent: false,
			Icon:                appIcon,
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting IAM Scanner UI:", err)
		os.Exit(1)
	}
}

// writeFile is a small helper used by App.SaveFile to write string content to
// disk. Kept here (not in app.go) because it is purely an I/O utility that
// requires no App state.
func writeFile(path, content string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}
