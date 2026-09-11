package i18n

import (
	"os"
	"strings"
)

// SupportedLocales lists the languages the project is prepared to serve across
// the marketing site, desktop configurator, and notification payloads.
var SupportedLocales = []string{"en", "sv", "nb", "fi", "da", "is"}

var localeAliases = map[string]string{
	"en": "en", "en_us": "en", "en_gb": "en", "en_au": "en", "en_ca": "en",
	"sv": "sv", "sv_se": "sv", "sv_fi": "sv",
	"nb": "nb", "no": "nb", "nn": "nb", "nb_no": "nb", "no_no": "nb",
	"fi": "fi", "fi_fi": "fi",
	"da": "da", "da_dk": "da",
	"is": "is", "is_is": "is",
}

var catalog = map[string]map[string]string{
	"app.title": {
		"en": "Viking Bio – Device Configurator",
		"sv": "Viking Bio – Enhetskonfigurator",
		"nb": "Viking Bio – Enhetskonfigurasjon",
		"fi": "Viking Bio – Laitteen konfigurointi",
		"da": "Viking Bio – Enhedskonfiguration",
		"is": "Viking Bio – Tækjakonfígúra",
	},
	"app.provisioning.title": {
		"en": "Viking Bio – Provisioning over USB",
		"sv": "Viking Bio – Provisionering via USB",
		"nb": "Viking Bio – Provisionering via USB",
		"fi": "Viking Bio – Provisionointi USB:n kautta",
		"da": "Viking Bio – Provisionering via USB",
		"is": "Viking Bio – Umskipting yfir USB",
	},
	"app.monitor.title": {
		"en": "Viking Bio – Network Telemetry",
		"sv": "Viking Bio – Nätverkstelemetri",
		"nb": "Viking Bio – Nettverkstelemetri",
		"fi": "Viking Bio – Verkkotelemetria",
		"da": "Viking Bio – Netværkstelemetri",
		"is": "Viking Bio – Netverkstelemetrý",
	},
	"app.version": {
		"en": "Version: %s",
		"sv": "Version: %s",
		"nb": "Versjon: %s",
		"fi": "Versio: %s",
		"da": "Version: %s",
		"is": "Útgáfa: %s",
	},
	"menu.show_status": {
		"en": "Show device status",
		"sv": "Visa enhetsstatus",
		"nb": "Vis enhetsstatus",
		"fi": "Näytä laitteen tila",
		"da": "Vis enhedens status",
		"is": "Sýna stöðu tækis",
	},
	"menu.configure_wifi": {
		"en": "Configure WiFi (SSID + password)",
		"sv": "Konfigurera WiFi (SSID + lösenord)",
		"nb": "Konfigurer WiFi (SSID + passord)",
		"fi": "Määritä WiFi (SSID + salasana)",
		"da": "Konfigurer WiFi (SSID + adgangskode)",
		"is": "Stilla inn WiFi (SSID + lykilorð)",
	},
	"menu.set_country": {
		"en": "Set Wi-Fi country code",
		"sv": "Ställ in Wi‑Fi-landskod",
		"nb": "Angi Wi‑Fi-landkode",
		"fi": "Aseta Wi‑Fi-maakoodi",
		"da": "Angiv Wi‑Fi-landekode",
		"is": "Stilla Wi‑Fi landskóða",
	},
	"menu.set_server": {
		"en": "Set server address & port",
		"sv": "Ställ in serveradress och port",
		"nb": "Angi tjeneradresse og port",
		"fi": "Aseta palvelimen osoite ja portti",
		"da": "Angiv serveradresse og port",
		"is": "Stilla veffang og gátt",
	},
	"menu.set_webhook": {
		"en": "Set webhook URL",
		"sv": "Ställ in webhook-URL",
		"nb": "Angi webhook-URL",
		"fi": "Aseta webhook-URL",
		"da": "Angiv webhook-URL",
		"is": "Stilla webhook URL",
	},
	"menu.provision_key": {
		"en": "Provision telemetry device key",
		"sv": "Provisionera enhetsnyckel för telemetri",
		"nb": "Tilordne telemetri-enhetsnøkkel",
		"fi": "Määritä telemetrian laiteavain",
		"da": "Tildel enheds-nøgle til telemetri",
		"is": "Úthluta lyklinum fyrir telemetríu",
	},
	"menu.clear_credentials": {
		"en": "Clear all credentials",
		"sv": "Rensa alla autentiseringsuppgifter",
		"nb": "Slett alle legitimasjoner",
		"fi": "Tyhjennä kaikki tunnistetiedot",
		"da": "Slet alle legitimationsoplysninger",
		"is": "Hreinsa öll auðkenni",
	},
	"menu.show_telemetry": {
		"en": "Show live telemetry",
		"sv": "Visa live-telemetri",
		"nb": "Vis live-telemetri",
		"fi": "Näytä reaaliaikainen telemetria",
		"da": "Vis live-telemetri",
		"is": "Sýna rauntíma telemetríu",
	},
	"menu.exit": {
		"en": "Exit",
		"sv": "Avsluta",
		"nb": "Avslutt",
		"fi": "Sulje",
		"da": "Luk",
		"is": "Loka",
	},
	"menu.choice": {
		"en": "Choice: ",
		"sv": "Val: ",
		"nb": "Valg: ",
		"fi": "Valinta: ",
		"da": "Valg: ",
		"is": "Val: ",
	},
	"status.loading": {
		"en": "Loading device status...",
		"sv": "Laddar enhetsstatus...",
		"nb": "Laster enhetsstatus...",
		"fi": "Ladataan laitteen tilaa...",
		"da": "Indlæser enhedsstatus...",
		"is": "Hleð inn stöðu tækis...",
	},
	"status.connected": {
		"en": "connected",
		"sv": "ansluten",
		"nb": "tilkoblet",
		"fi": "yhdistetty",
		"da": "forbundet",
		"is": "tengt",
	},
	"status.disconnected": {
		"en": "not connected",
		"sv": "ej ansluten",
		"nb": "ikke tilkoblet",
		"fi": "ei yhdistetty",
		"da": "ikke forbundet",
		"is": "ekki tengt",
	},
	"status.device": {
		"en": "Device Status:",
		"sv": "Enhetsstatus:",
		"nb": "Enhetsstatus:",
		"fi": "Laitteen tila:",
		"da": "Enhedsstatus:",
		"is": "Staða tækis:",
	},
	"status.waiting": {
		"en": "Waiting for telemetry... No data has been received yet.",
		"sv": "Väntar på telemetri... Ingen data har mottagits ännu.",
		"nb": "Venter på telemetri... Ingen data er mottatt ennå.",
		"fi": "Odotetaan telemetriaa... Ei dataa ole vielä vastaanotettu.",
		"da": "Venter på telemetri... Ingen data er modtaget endnu.",
		"is": "Bíð eftir telemetríu... Engin gögn hafa borist enn.",
	},
	"telemetry.title": {
		"en": "Live burner telemetry:",
		"sv": "Live telemetri för brännare:",
		"nb": "Direkte brennertelemetri:",
		"fi": "Reaaliaikainen polttimen telemetria:",
		"da": "Live brænder-telemetri:",
		"is": "Rauntíma telemetría brennarans:",
	},
	"telemetry.unavailable": {
		"en": "Live telemetry is unavailable; the configurator is not connected to a live telemetry stream.",
		"sv": "Live-telemetri är inte tillgänglig; konfiguratorn är inte ansluten till en live telemetri-ström.",
		"nb": "Live-telemetri er ikke tilgjengelig; konfigurasjonen er ikke koblet til en aktiv telemetri-strøm.",
		"fi": "Reaaliaikainen telemetria ei ole käytettävissä; konfiguraattori ei ole yhteydessä live-telemetriavirtaan.",
		"da": "Live-telemetri er ikke tilgængelig; konfigurationen er ikke forbundet til en aktiv telemetri-strøm.",
		"is": "Rauntíma telemetría er ekki tiltæk; stillingin er ekki tengd við lifandi telemetríu.",
	},
	"button.close": {
		"en": "Close",
		"sv": "Stäng",
		"nb": "Lukk",
		"fi": "Sulje",
		"da": "Luk",
		"is": "Loka",
	},
	"action.cancelled": {
		"en": "Cancelled.",
		"sv": "Avbrutet.",
		"nb": "Avbrutt.",
		"fi": "Peruutettu.",
		"da": "Annulleret.",
		"is": "Hætt var við.",
	},
	"action.done": {
		"en": "Done",
		"sv": "Klar",
		"nb": "Ferdig",
		"fi": "Valmis",
		"da": "Færdig",
		"is": "Lokið",
	},
	"action.save": {
		"en": "Save",
		"sv": "Spara",
		"nb": "Lagre",
		"fi": "Tallenna",
		"da": "Gem",
		"is": "Vista",
	},
	"action.set": {
		"en": "Set",
		"sv": "Ställ in",
		"nb": "Angi",
		"fi": "Aseta",
		"da": "Angiv",
		"is": "Stilla",
	},
	"action.cancel": {
		"en": "Cancel",
		"sv": "Avbryt",
		"nb": "Avbryt",
		"fi": "Peruuta",
		"da": "Annuller",
		"is": "Hætta við",
	},
	"form.ssid": {
		"en": "SSID",
		"sv": "SSID",
		"nb": "SSID",
		"fi": "SSID",
		"da": "SSID",
		"is": "SSID",
	},
	"form.password": {
		"en": "Password",
		"sv": "Lösenord",
		"nb": "Passord",
		"fi": "Salasana",
		"da": "Adgangskode",
		"is": "Lykilorð",
	},
	"form.wifi_region": {
		"en": "Wi‑Fi region",
		"sv": "Wi‑Fi-region",
		"nb": "Wi‑Fi-region",
		"fi": "Wi‑Fi-alue",
		"da": "Wi‑Fi-region",
		"is": "Wi‑Fi svæði",
	},
	"form.server_address": {
		"en": "Server IP/hostname",
		"sv": "Server-IP/värdnamn",
		"nb": "Server-IP/vertsnavn",
		"fi": "Palvelimen IP/verkkoisäntä",
		"da": "Server-IP/hostname",
		"is": "IP/vefnafn miðlara",
	},
	"form.port": {
		"en": "Port",
		"sv": "Port",
		"nb": "Port",
		"fi": "Portti",
		"da": "Port",
		"is": "Gátt",
	},
	"form.webhook_url": {
		"en": "Webhook URL",
		"sv": "Webhook-URL",
		"nb": "Webhook-URL",
		"fi": "Webhook-URL",
		"da": "Webhook-URL",
		"is": "Webhook URL",
	},
}

func Supported() []string {
	out := make([]string, len(SupportedLocales))
	copy(out, SupportedLocales)
	return out
}

func ResolveLocale(preferred string) string {
	locale := strings.TrimSpace(preferred)
	if locale == "" {
		locale = os.Getenv("LANG")
	}
	if locale == "" {
		return "en"
	}
	locale = strings.ToLower(locale)
	if idx := strings.IndexAny(locale, ".@"); idx >= 0 {
		locale = locale[:idx]
	}
	locale = strings.ReplaceAll(locale, "-", "_")
	if v, ok := localeAliases[locale]; ok {
		return v
	}
	for _, candidate := range SupportedLocales {
		if strings.HasPrefix(locale, candidate) {
			return candidate
		}
	}
	return "en"
}

func Lookup(locale, key string) string {
	resolved := ResolveLocale(locale)
	if entries, ok := catalog[key]; ok {
		if value, ok := entries[resolved]; ok && value != "" {
			return value
		}
		if value, ok := entries["en"]; ok && value != "" {
			return value
		}
	}
	return key
}
