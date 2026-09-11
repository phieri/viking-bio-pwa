package i18n

import "testing"

func TestResolveLocale(t *testing.T) {
	cases := map[string]string{
		"sv_SE.UTF-8": "sv",
		"no_NO":       "nb",
		"fi_FI":       "fi",
		"da_DK":       "da",
		"is_IS":       "is",
		"en_US":       "en",
		"de_DE":       "en",
	}
	for input, want := range cases {
		if got := ResolveLocale(input); got != want {
			t.Fatalf("ResolveLocale(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestLookupUsesLanguageSpecificStrings(t *testing.T) {
	if got := Lookup("sv", "menu.exit"); got != "Avsluta" {
		t.Fatalf("Lookup(sv, menu.exit) = %q, want %q", got, "Avsluta")
	}
	if got := Lookup("fi", "menu.show_status"); got != "Näytä laitteen tila" {
		t.Fatalf("Lookup(fi, menu.show_status) = %q, want %q", got, "Näytä laitteen tila")
	}
	if got := Lookup("fr", "menu.exit"); got != "Exit" {
		t.Fatalf("Lookup(fr, menu.exit) = %q, want %q", got, "Exit")
	}
}
