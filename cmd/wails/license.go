package main

// LicenseStatusDTO is returned by GetLicenseStatus and ActivateLicense.
//
// This build is fully open-source: all features are unconditionally
// available and no license is required. These methods are kept so the
// existing frontend (which still calls them) does not break; they always
// report an unlocked, all-features-enabled state.
type LicenseStatusDTO struct {
	Licensed bool   `json:"licensed"`
	Email    string `json:"email,omitempty"`
	Exp      string `json:"exp,omitempty"` // YYYY-MM-DD; empty means perpetual
}

// GetLicenseStatus always reports the app as fully licensed - there is no
// license gating in this open-source build.
func (a *App) GetLicenseStatus() LicenseStatusDTO {
	return LicenseStatusDTO{Licensed: true}
}

// ActivateLicense is a no-op kept for frontend backward compatibility. All
// features are already unconditionally enabled, so this simply reports the
// always-unlocked state regardless of the input.
func (a *App) ActivateLicense(email, key string) LicenseStatusDTO {
	return LicenseStatusDTO{Licensed: true}
}
