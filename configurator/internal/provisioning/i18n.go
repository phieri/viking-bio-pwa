/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

package provisioning

import (
    "fmt"
    "os"
    "strings"

    "golang.org/x/text/language"
    "golang.org/x/text/language/display"
)

const defaultProvisioningLanguage = "en"

var supportedProvisioningLanguages = []string{"en", "sv", "no", "fi", "da", "is"}

var supportedProvisioningLanguageNames = map[string]string{
    "en": "English",
    "sv": "Svenska",
    "no": "Norsk",
    "fi": "Suomi",
    "da": "Dansk",
    "is": "Íslenska",
}

var provisioningMessages = map[string]map[string]string{
    "en": {
        "app.language":                          "Language",
        "app.window.provisioning":               "Viking Bio – Provisioning over USB",
        "app.window.telemetry":                  "Viking Bio – Network Telemetry",
        "app.title":                             "Viking Bio – Device Configurator",
        "app.version":                           "Configurator: %s",
        "status.loading":                        "Loading device status...",
        "status.unavailable.offline":            "Status unavailable: no Pico serial port is connected.\nConnect a device over USB or set PICO_SERIAL_PORT to enable live configuration.\nThe configurator is running in offline/network mode.",
        "status.unavailable.error":              "Status unavailable: %s",
        "status.wifi.connected":                 "connected",
        "status.wifi.disconnected":              "not connected",
        "status.telemetry.waiting":              "Waiting for telemetry...",
        "status.telemetry.unavailable":          "Waiting for telemetry...\nThe server is not connected to a live telemetry stream.",
        "status.telemetry.empty":                "Waiting for telemetry...\nNo data has been received yet.",
        "status.live_telemetry_unavailable":     "Live telemetry is unavailable; the configurator is not connected to a live telemetry stream.",
        "status.live_telemetry_empty":           "  Waiting for telemetry... No data has been received yet.",
        "status.last_contact":                   "Last update",
        "button.show_status":                    "Show device status",
        "button.configure_wifi":                 "Configure WiFi",
        "button.set_country":                    "Set country code",
        "button.set_server":                     "Set server address & port",
        "button.set_webhook":                    "Set webhook URL",
        "button.provision_key":                  "Provision telemetry device key",
        "button.clear_credentials":              "Clear all credentials",
        "button.close":                          "Close",
        "dialog.save":                           "Save",
        "dialog.cancel":                         "Cancel",
        "dialog.set":                            "Set",
        "dialog.done":                           "Done",
        "dialog.provisioned":                    "Provisioned",
        "dialog.wifi.title":                     "Configure WiFi",
        "dialog.wifi.saved_title":               "WiFi configured",
        "dialog.wifi.saved_body":                "Credentials saved. Device will reboot.",
        "dialog.country.title":                  "Set Wi-Fi country code",
        "dialog.server.title":                   "Set server",
        "dialog.webhook.title":                  "Set webhook URL",
        "dialog.clear.title":                    "Clear credentials",
        "dialog.clear.body":                     "This will erase all stored credentials and reboot the device.\nAre you sure?",
        "form.ssid":                             "SSID",
        "form.password":                         "Password",
        "form.server":                           "Server IP/hostname",
        "form.port":                             "Port",
        "form.webhook":                          "Webhook URL",
        "form.region":                           "Wi-Fi region",
        "placeholder.ssid":                      "MyNetwork",
        "placeholder.password":                  "password",
        "placeholder.server":                    "192.168.1.10 or fd00::1",
        "placeholder.webhook":                   "https://hooks.example.com/secret",
        "error.blank_ssid":                      "SSID must not be empty",
        "error.blank_server":                    "server address must not be empty",
        "error.invalid_webhook":                 "webhook URL must start with http:// or https://",
        "error.reading_status":                  "Error reading status: %s",
        "error.generating_key":                  "Error generating device key: %s",
        "error.storing_key":                     "Error storing device key: %s",
        "error.device_id_missing":               "Device ID missing from STATUS output.",
        "error.unknown_option":                  "Unknown option.",
        "menu.option1":                          "Show device status",
        "menu.option2":                          "Configure WiFi (SSID + password)",
        "menu.option3":                          "Set Wi-Fi country code",
        "menu.option4":                          "Set server address & port",
        "menu.option5":                          "Set webhook URL",
        "menu.option6":                          "Provision telemetry device key",
        "menu.option7":                          "Clear all credentials",
        "menu.option8":                          "Show live telemetry",
        "menu.option0":                          "Exit",
        "menu.choice":                           "Choice: ",
        "tui.device_status":                     "Device Status:",
        "tui.live_telemetry":                    "Live burner telemetry:",
        "tui.cancelled":                         "Cancelled.",
        "tui.credentials_saved":                 "Credentials saved. Device will reboot.",
        "tui.country_prompt":                    "Country code (e.g. SE, US): ",
        "tui.invalid_country":                   "Invalid country code (must be 2 letters).",
        "tui.server_prompt":                     "Server IP/hostname: ",
        "tui.server_port_prompt":                "Server port [9000]: ",
        "tui.webhook_prompt":                    "Webhook URL (http:// or https://): ",
        "tui.invalid_webhook":                   "Webhook URL must start with http:// or https://.",
        "tui.telemetry_provisioned":             "Telemetry key provisioned for %s.",
        "tui.clear_confirm":                     "Type YES to confirm clearing all credentials: ",
        "tui.credentials_cleared":               "Credentials cleared. Device will reboot.",
        "tui.bye":                               "Bye!",
        "telemetry.title":                       "Network telemetry",
        "telemetry.label":                       "Live burner telemetry",
        "telemetry.error.notification_title":    "Viking Bio – burner error",
        "telemetry.error.notification_body":     "New burner error code: %.0f",
        "field.wifi":                            "WiFi",
        "field.address":                         "Address",
        "field.country":                         "Country",
        "field.device":                          "Device",
        "field.firmware":                        "Firmware",
        "field.server":                          "Server",
        "field.telemetry":                       "Telemetry",
        "field.device_key":                      "DeviceKey",
        "field.webhook":                         "Webhook",
        "field.flame":                           "Flame",
        "field.fan":                             "Fan",
        "field.temp":                            "Temp",
        "field.err":                             "Err",
        "field.valid":                           "Valid",
        "field.flame_seconds":                   "Flame seconds",
        "region.worldwide":                      "Worldwide",
    },
    "sv": {
        "app.language":                       "Språk",
        "app.window.provisioning":            "Viking Bio – USB-provisionering",
        "app.window.telemetry":               "Viking Bio – Nätverkstelemetri",
        "app.title":                          "Viking Bio – Enhetskonfigurator",
        "app.version":                        "Konfigurator: %s",
        "status.loading":                     "Läser enhetsstatus...",
        "status.unavailable.offline":         "Status är inte tillgänglig: ingen Pico-serieport är ansluten.\nAnslut en enhet via USB eller ange PICO_SERIAL_PORT för att aktivera livekonfiguration.\nKonfiguratorn körs i offline-/nätverksläge.",
        "status.unavailable.error":           "Status är inte tillgänglig: %s",
        "status.wifi.connected":              "ansluten",
        "status.wifi.disconnected":           "inte ansluten",
        "status.telemetry.waiting":           "Väntar på telemetri...",
        "status.telemetry.unavailable":       "Väntar på telemetri...\nServern är inte ansluten till en live-telemetriström.",
        "status.telemetry.empty":             "Väntar på telemetri...\nIngen data har tagits emot ännu.",
        "status.live_telemetry_unavailable":  "Live-telemetri är inte tillgänglig; konfiguratorn är inte ansluten till en live-telemetriström.",
        "status.live_telemetry_empty":        "  Väntar på telemetri... Ingen data har tagits emot ännu.",
        "status.last_contact":                "Senaste uppdatering",
        "button.show_status":                 "Visa enhetsstatus",
        "button.configure_wifi":              "Konfigurera Wi‑Fi",
        "button.set_country":                 "Ange landskod",
        "button.set_server":                  "Ange serveradress och port",
        "button.set_webhook":                 "Ange webhook-URL",
        "button.provision_key":               "Provisionera telemetrienhetsnyckel",
        "button.clear_credentials":           "Rensa alla uppgifter",
        "button.close":                       "Stäng",
        "dialog.save":                        "Spara",
        "dialog.cancel":                      "Avbryt",
        "dialog.set":                         "Ange",
        "dialog.done":                        "Klart",
        "dialog.provisioned":                 "Provisionerad",
        "dialog.wifi.title":                  "Konfigurera Wi‑Fi",
        "dialog.wifi.saved_title":            "Wi‑Fi konfigurerat",
        "dialog.wifi.saved_body":             "Uppgifterna har sparats. Enheten startar om.",
        "dialog.country.title":               "Ange Wi‑Fi-landskod",
        "dialog.server.title":                "Ange server",
        "dialog.webhook.title":               "Ange webhook-URL",
        "dialog.clear.title":                 "Rensa uppgifter",
        "dialog.clear.body":                  "Detta raderar alla sparade uppgifter och startar om enheten.\nÄr du säker?",
        "form.ssid":                          "SSID",
        "form.password":                      "Lösenord",
        "form.server":                        "Server-IP/värdnamn",
        "form.port":                          "Port",
        "form.webhook":                       "Webhook-URL",
        "form.region":                        "Wi‑Fi-region",
        "placeholder.ssid":                   "MittNätverk",
        "placeholder.password":               "lösenord",
        "placeholder.server":                 "192.168.1.10 eller fd00::1",
        "placeholder.webhook":                "https://hooks.example.com/hemlig",
        "error.blank_ssid":                   "SSID får inte vara tomt",
        "error.blank_server":                 "serveradressen får inte vara tom",
        "error.invalid_webhook":              "webhook-URL måste börja med http:// eller https://",
        "error.reading_status":               "Fel vid läsning av status: %s",
        "error.generating_key":               "Fel vid generering av enhetsnyckel: %s",
        "error.storing_key":                  "Fel vid lagring av enhetsnyckel: %s",
        "error.device_id_missing":            "Enhets-ID saknas i STATUS-utdata.",
        "error.unknown_option":               "Okänt val.",
        "menu.option1":                       "Visa enhetsstatus",
        "menu.option2":                       "Konfigurera Wi‑Fi (SSID + lösenord)",
        "menu.option3":                       "Ange Wi‑Fi-landskod",
        "menu.option4":                       "Ange serveradress och port",
        "menu.option5":                       "Ange webhook-URL",
        "menu.option6":                       "Provisionera telemetrienhetsnyckel",
        "menu.option7":                       "Rensa alla uppgifter",
        "menu.option8":                       "Visa live-telemetri",
        "menu.option0":                       "Avsluta",
        "menu.choice":                        "Val: ",
        "tui.device_status":                  "Enhetsstatus:",
        "tui.live_telemetry":                 "Live-telemetri från brännaren:",
        "tui.cancelled":                      "Avbrutet.",
        "tui.credentials_saved":              "Uppgifterna har sparats. Enheten startar om.",
        "tui.country_prompt":                 "Landskod (t.ex. SE, US): ",
        "tui.invalid_country":                "Ogiltig landskod (måste vara 2 bokstäver).",
        "tui.server_prompt":                  "Server-IP/värdnamn: ",
        "tui.server_port_prompt":             "Serverport [9000]: ",
        "tui.webhook_prompt":                 "Webhook-URL (http:// eller https://): ",
        "tui.invalid_webhook":                "Webhook-URL måste börja med http:// eller https://.",
        "tui.telemetry_provisioned":          "Telemetrinyckel provisionerad för %s.",
        "tui.clear_confirm":                  "Skriv YES för att bekräfta rensning av alla uppgifter: ",
        "tui.credentials_cleared":            "Uppgifterna har rensats. Enheten startar om.",
        "tui.bye":                            "Hej då!",
        "telemetry.title":                    "Nätverkstelemetri",
        "telemetry.label":                    "Live-telemetri från brännaren",
        "telemetry.error.notification_title": "Viking Bio – brännarfel",
        "telemetry.error.notification_body":  "Ny felkod från brännaren: %.0f",
        "region.worldwide":                   "Världen",
    },
    "no": {
        "app.language":                       "Språk",
        "app.window.provisioning":            "Viking Bio – USB-klargjøring",
        "app.window.telemetry":               "Viking Bio – Nettverkstelemetri",
        "app.title":                          "Viking Bio – Enhetskonfigurator",
        "app.version":                        "Konfigurator: %s",
        "status.loading":                     "Laster enhetsstatus...",
        "status.unavailable.offline":         "Status er utilgjengelig: ingen Pico-serieport er koblet til.\nKoble til en enhet via USB eller angi PICO_SERIAL_PORT for å aktivere direkte konfigurering.\nKonfiguratoren kjører i frakoblet/nettverksmodus.",
        "status.unavailable.error":           "Status er utilgjengelig: %s",
        "status.wifi.connected":              "tilkoblet",
        "status.wifi.disconnected":           "ikke tilkoblet",
        "status.telemetry.waiting":           "Venter på telemetri...",
        "status.telemetry.unavailable":       "Venter på telemetri...\nServeren er ikke koblet til en direkte telemetristøm.",
        "status.telemetry.empty":             "Venter på telemetri...\nIngen data er mottatt ennå.",
        "status.live_telemetry_unavailable":  "Direkte telemetri er utilgjengelig; konfiguratoren er ikke koblet til en direkte telemetristøm.",
        "status.live_telemetry_empty":        "  Venter på telemetri... Ingen data er mottatt ennå.",
        "status.last_contact":                "Siste oppdatering",
        "button.show_status":                 "Vis enhetsstatus",
        "button.configure_wifi":              "Konfigurer Wi‑Fi",
        "button.set_country":                 "Angi landskode",
        "button.set_server":                  "Angi serveradresse og port",
        "button.set_webhook":                 "Angi webhook-URL",
        "button.provision_key":               "Klargjør telemetrienhetsnøkkel",
        "button.clear_credentials":           "Fjern alle legitimasjoner",
        "button.close":                       "Lukk",
        "dialog.save":                        "Lagre",
        "dialog.cancel":                      "Avbryt",
        "dialog.set":                         "Angi",
        "dialog.done":                        "Ferdig",
        "dialog.provisioned":                 "Klargjort",
        "dialog.wifi.title":                  "Konfigurer Wi‑Fi",
        "dialog.wifi.saved_title":            "Wi‑Fi konfigurert",
        "dialog.wifi.saved_body":             "Opplysningene er lagret. Enheten vil starte på nytt.",
        "dialog.country.title":               "Angi Wi‑Fi-landskode",
        "dialog.server.title":                "Angi server",
        "dialog.webhook.title":               "Angi webhook-URL",
        "dialog.clear.title":                 "Fjern legitimasjoner",
        "dialog.clear.body":                  "Dette vil slette alle lagrede legitimasjoner og starte enheten på nytt.\nEr du sikker?",
        "form.ssid":                          "SSID",
        "form.password":                      "Passord",
        "form.server":                        "Server-IP/vertsnavn",
        "form.port":                          "Port",
        "form.webhook":                       "Webhook-URL",
        "form.region":                        "Wi‑Fi-region",
        "placeholder.ssid":                   "MittNettverk",
        "placeholder.password":               "passord",
        "placeholder.server":                 "192.168.1.10 eller fd00::1",
        "placeholder.webhook":                "https://hooks.example.com/hemmelig",
        "error.blank_ssid":                   "SSID kan ikke være tom",
        "error.blank_server":                 "serveradressen kan ikke være tom",
        "error.invalid_webhook":              "webhook-URL må starte med http:// eller https://",
        "error.reading_status":               "Feil ved lesing av status: %s",
        "error.generating_key":               "Feil ved oppretting av enhetsnøkkel: %s",
        "error.storing_key":                  "Feil ved lagring av enhetsnøkkel: %s",
        "error.device_id_missing":            "Enhets-ID mangler i STATUS-utdata.",
        "error.unknown_option":               "Ukjent valg.",
        "menu.option1":                       "Vis enhetsstatus",
        "menu.option2":                       "Konfigurer Wi‑Fi (SSID + passord)",
        "menu.option3":                       "Angi Wi‑Fi-landskode",
        "menu.option4":                       "Angi serveradresse og port",
        "menu.option5":                       "Angi webhook-URL",
        "menu.option6":                       "Klargjør telemetrienhetsnøkkel",
        "menu.option7":                       "Fjern alle legitimasjoner",
        "menu.option8":                       "Vis direkte telemetri",
        "menu.option0":                       "Avslutt",
        "menu.choice":                        "Valg: ",
        "tui.device_status":                  "Enhetsstatus:",
        "tui.live_telemetry":                 "Direkte brennertelemetri:",
        "tui.cancelled":                      "Avbrutt.",
        "tui.credentials_saved":              "Opplysningene er lagret. Enheten vil starte på nytt.",
        "tui.country_prompt":                 "Landskode (f.eks. SE, US): ",
        "tui.invalid_country":                "Ugyldig landskode (må være 2 bokstaver).",
        "tui.server_prompt":                  "Server-IP/vertsnavn: ",
        "tui.server_port_prompt":             "Serverport [9000]: ",
        "tui.webhook_prompt":                 "Webhook-URL (http:// eller https://): ",
        "tui.invalid_webhook":                "Webhook-URL må starte med http:// eller https://.",
        "tui.telemetry_provisioned":          "Telemetrinøkkel klargjort for %s.",
        "tui.clear_confirm":                  "Skriv YES for å bekrefte sletting av alle legitimasjoner: ",
        "tui.credentials_cleared":            "Legitimasjonene er slettet. Enheten vil starte på nytt.",
        "tui.bye":                            "Ha det!",
        "telemetry.title":                    "Nettverkstelemetri",
        "telemetry.label":                    "Direkte brennertelemetri",
        "telemetry.error.notification_title": "Viking Bio – brennerfeil",
        "telemetry.error.notification_body":  "Ny feilkode fra brenneren: %.0f",
        "region.worldwide":                   "Hele verden",
    },
    "fi": {
        "app.language":                       "Kieli",
        "app.window.provisioning":            "Viking Bio – USB-käyttöönotto",
        "app.window.telemetry":               "Viking Bio – Verkkotelemetria",
        "app.title":                          "Viking Bio – Laitekonfiguraattori",
        "app.version":                        "Konfiguraattori: %s",
        "status.loading":                     "Ladataan laitteen tilaa...",
        "status.unavailable.offline":         "Tila ei ole saatavilla: Pico-sarjaporttia ei ole liitetty.\nLiitä laite USB:n kautta tai määritä PICO_SERIAL_PORT ottaaksesi live-määrityksen käyttöön.\nKonfiguraattori toimii offline-/verkkotilassa.",
        "status.unavailable.error":           "Tila ei ole saatavilla: %s",
        "status.wifi.connected":              "yhdistetty",
        "status.wifi.disconnected":           "ei yhdistetty",
        "status.telemetry.waiting":           "Odotetaan telemetriaa...",
        "status.telemetry.unavailable":       "Odotetaan telemetriaa...\nPalvelin ei ole yhteydessä reaaliaikaiseen telemetriavirtaan.",
        "status.telemetry.empty":             "Odotetaan telemetriaa...\nTietoja ei ole vielä vastaanotettu.",
        "status.live_telemetry_unavailable":  "Reaaliaikainen telemetria ei ole käytettävissä; konfiguraattori ei ole yhteydessä reaaliaikaiseen telemetriavirtaan.",
        "status.live_telemetry_empty":        "  Odotetaan telemetriaa... Tietoja ei ole vielä vastaanotettu.",
        "status.last_contact":                "Viimeisin päivitys",
        "button.show_status":                 "Näytä laitteen tila",
        "button.configure_wifi":              "Määritä Wi‑Fi",
        "button.set_country":                 "Aseta maakoodi",
        "button.set_server":                  "Aseta palvelinosoite ja portti",
        "button.set_webhook":                 "Aseta webhook-URL",
        "button.provision_key":               "Ota telemetria-avain käyttöön",
        "button.clear_credentials":           "Tyhjennä kaikki tunnistetiedot",
        "button.close":                       "Sulje",
        "dialog.save":                        "Tallenna",
        "dialog.cancel":                      "Peruuta",
        "dialog.set":                         "Aseta",
        "dialog.done":                        "Valmis",
        "dialog.provisioned":                 "Käyttöönotettu",
        "dialog.wifi.title":                  "Määritä Wi‑Fi",
        "dialog.wifi.saved_title":            "Wi‑Fi määritetty",
        "dialog.wifi.saved_body":             "Tiedot tallennettiin. Laite käynnistyy uudelleen.",
        "dialog.country.title":               "Aseta Wi‑Fi-maakoodi",
        "dialog.server.title":                "Aseta palvelin",
        "dialog.webhook.title":               "Aseta webhook-URL",
        "dialog.clear.title":                 "Tyhjennä tunnistetiedot",
        "dialog.clear.body":                  "Tämä poistaa kaikki tallennetut tunnistetiedot ja käynnistää laitteen uudelleen.\nOletko varma?",
        "form.ssid":                          "SSID",
        "form.password":                      "Salasana",
        "form.server":                        "Palvelimen IP/isäntänimi",
        "form.port":                          "Portti",
        "form.webhook":                       "Webhook-URL",
        "form.region":                        "Wi‑Fi-alue",
        "placeholder.ssid":                   "OmaVerkko",
        "placeholder.password":               "salasana",
        "placeholder.server":                 "192.168.1.10 tai fd00::1",
        "placeholder.webhook":                "https://hooks.example.com/salainen",
        "error.blank_ssid":                   "SSID ei saa olla tyhjä",
        "error.blank_server":                 "palvelinosoite ei saa olla tyhjä",
        "error.invalid_webhook":              "webhook-URL:n on alettava muodolla http:// tai https://",
        "error.reading_status":               "Virhe tilaa luettaessa: %s",
        "error.generating_key":               "Virhe laiteavainta luotaessa: %s",
        "error.storing_key":                  "Virhe laiteavainta tallennettaessa: %s",
        "error.device_id_missing":            "Laitetunnus puuttuu STATUS-tulosteesta.",
        "error.unknown_option":               "Tuntematon valinta.",
        "menu.option1":                       "Näytä laitteen tila",
        "menu.option2":                       "Määritä Wi‑Fi (SSID + salasana)",
        "menu.option3":                       "Aseta Wi‑Fi-maakoodi",
        "menu.option4":                       "Aseta palvelinosoite ja portti",
        "menu.option5":                       "Aseta webhook-URL",
        "menu.option6":                       "Ota telemetria-avain käyttöön",
        "menu.option7":                       "Tyhjennä kaikki tunnistetiedot",
        "menu.option8":                       "Näytä reaaliaikainen telemetria",
        "menu.option0":                       "Poistu",
        "menu.choice":                        "Valinta: ",
        "tui.device_status":                  "Laitteen tila:",
        "tui.live_telemetry":                 "Polttimen reaaliaikainen telemetria:",
        "tui.cancelled":                      "Peruttu.",
        "tui.credentials_saved":              "Tiedot tallennettiin. Laite käynnistyy uudelleen.",
        "tui.country_prompt":                 "Maakoodi (esim. SE, US): ",
        "tui.invalid_country":                "Virheellinen maakoodi (oltava 2 kirjainta).",
        "tui.server_prompt":                  "Palvelimen IP/isäntänimi: ",
        "tui.server_port_prompt":             "Palvelinportti [9000]: ",
        "tui.webhook_prompt":                 "Webhook-URL (http:// tai https://): ",
        "tui.invalid_webhook":                "Webhook-URL:n on alettava muodolla http:// tai https://.",
        "tui.telemetry_provisioned":          "Telemetria-avain otettiin käyttöön laitteelle %s.",
        "tui.clear_confirm":                  "Kirjoita YES vahvistaaksesi kaikkien tunnistetietojen poiston: ",
        "tui.credentials_cleared":            "Tunnistetiedot poistettiin. Laite käynnistyy uudelleen.",
        "tui.bye":                            "Hei!",
        "telemetry.title":                    "Verkkotelemetria",
        "telemetry.label":                    "Polttimen reaaliaikainen telemetria",
        "telemetry.error.notification_title": "Viking Bio – polttimen virhe",
        "telemetry.error.notification_body":  "Uusi polttimen virhekoodi: %.0f",
        "region.worldwide":                   "Maailmanlaajuinen",
    },
    "da": {
        "app.language":                       "Sprog",
        "app.window.provisioning":            "Viking Bio – USB-klargøring",
        "app.window.telemetry":               "Viking Bio – Netværkstelemetri",
        "app.title":                          "Viking Bio – Enhedskonfigurator",
        "app.version":                        "Konfigurator: %s",
        "status.loading":                     "Indlæser enhedsstatus...",
        "status.unavailable.offline":         "Status er utilgængelig: ingen Pico-serielport er tilsluttet.\nTilslut en enhed via USB eller angiv PICO_SERIAL_PORT for at aktivere live-konfiguration.\nKonfiguratoren kører i offline-/netværkstilstand.",
        "status.unavailable.error":           "Status er utilgængelig: %s",
        "status.wifi.connected":              "forbundet",
        "status.wifi.disconnected":           "ikke forbundet",
        "status.telemetry.waiting":           "Venter på telemetri...",
        "status.telemetry.unavailable":       "Venter på telemetri...\nServeren er ikke forbundet til en live-telemetristrøm.",
        "status.telemetry.empty":             "Venter på telemetri...\nDer er endnu ikke modtaget data.",
        "status.live_telemetry_unavailable":  "Live-telemetri er utilgængelig; konfiguratoren er ikke forbundet til en live-telemetristrøm.",
        "status.live_telemetry_empty":        "  Venter på telemetri... Der er endnu ikke modtaget data.",
        "status.last_contact":                "Seneste opdatering",
        "button.show_status":                 "Vis enhedsstatus",
        "button.configure_wifi":              "Konfigurer Wi‑Fi",
        "button.set_country":                 "Angiv landekode",
        "button.set_server":                  "Angiv serveradresse og port",
        "button.set_webhook":                 "Angiv webhook-URL",
        "button.provision_key":               "Klargør telemetrienhedsnøgle",
        "button.clear_credentials":           "Ryd alle legitimationsoplysninger",
        "button.close":                       "Luk",
        "dialog.save":                        "Gem",
        "dialog.cancel":                      "Annuller",
        "dialog.set":                         "Angiv",
        "dialog.done":                        "Færdig",
        "dialog.provisioned":                 "Klargjort",
        "dialog.wifi.title":                  "Konfigurer Wi‑Fi",
        "dialog.wifi.saved_title":            "Wi‑Fi konfigureret",
        "dialog.wifi.saved_body":             "Oplysningerne er gemt. Enheden genstarter.",
        "dialog.country.title":               "Angiv Wi‑Fi-landekode",
        "dialog.server.title":                "Angiv server",
        "dialog.webhook.title":               "Angiv webhook-URL",
        "dialog.clear.title":                 "Ryd legitimationsoplysninger",
        "dialog.clear.body":                  "Dette sletter alle gemte legitimationsoplysninger og genstarter enheden.\nEr du sikker?",
        "form.ssid":                          "SSID",
        "form.password":                      "Adgangskode",
        "form.server":                        "Server-IP/værtsnavn",
        "form.port":                          "Port",
        "form.webhook":                       "Webhook-URL",
        "form.region":                        "Wi‑Fi-region",
        "placeholder.ssid":                   "MitNetværk",
        "placeholder.password":               "adgangskode",
        "placeholder.server":                 "192.168.1.10 eller fd00::1",
        "placeholder.webhook":                "https://hooks.example.com/hemmelig",
        "error.blank_ssid":                   "SSID må ikke være tomt",
        "error.blank_server":                 "serveradressen må ikke være tom",
        "error.invalid_webhook":              "webhook-URL'en skal starte med http:// eller https://",
        "error.reading_status":               "Fejl ved læsning af status: %s",
        "error.generating_key":               "Fejl ved generering af enhedsnøgle: %s",
        "error.storing_key":                  "Fejl ved lagring af enhedsnøgle: %s",
        "error.device_id_missing":            "Enheds-ID mangler i STATUS-output.",
        "error.unknown_option":               "Ukendt valg.",
        "menu.option1":                       "Vis enhedsstatus",
        "menu.option2":                       "Konfigurer Wi‑Fi (SSID + adgangskode)",
        "menu.option3":                       "Angiv Wi‑Fi-landekode",
        "menu.option4":                       "Angiv serveradresse og port",
        "menu.option5":                       "Angiv webhook-URL",
        "menu.option6":                       "Klargør telemetrienhedsnøgle",
        "menu.option7":                       "Ryd alle legitimationsoplysninger",
        "menu.option8":                       "Vis live-telemetri",
        "menu.option0":                       "Afslut",
        "menu.choice":                        "Valg: ",
        "tui.device_status":                  "Enhedsstatus:",
        "tui.live_telemetry":                 "Live-telemetri fra brænderen:",
        "tui.cancelled":                      "Annulleret.",
        "tui.credentials_saved":              "Oplysningerne er gemt. Enheden genstarter.",
        "tui.country_prompt":                 "Landekode (f.eks. SE, US): ",
        "tui.invalid_country":                "Ugyldig landekode (skal være 2 bogstaver).",
        "tui.server_prompt":                  "Server-IP/værtsnavn: ",
        "tui.server_port_prompt":             "Serverport [9000]: ",
        "tui.webhook_prompt":                 "Webhook-URL (http:// eller https://): ",
        "tui.invalid_webhook":                "Webhook-URL'en skal starte med http:// eller https://.",
        "tui.telemetry_provisioned":          "Telemetrinøglen blev klargjort for %s.",
        "tui.clear_confirm":                  "Skriv YES for at bekræfte rydning af alle legitimationsoplysninger: ",
        "tui.credentials_cleared":            "Legitimationsoplysningerne blev ryddet. Enheden genstarter.",
        "tui.bye":                            "Farvel!",
        "telemetry.title":                    "Netværkstelemetri",
        "telemetry.label":                    "Live-telemetri fra brænderen",
        "telemetry.error.notification_title": "Viking Bio – brænderfejl",
        "telemetry.error.notification_body":  "Ny fejlkode fra brænderen: %.0f",
        "region.worldwide":                   "Verdensomspændende",
    },
    "is": {
        "app.language":                       "Tungumál",
        "app.window.provisioning":            "Viking Bio – USB-uppsetning",
        "app.window.telemetry":               "Viking Bio – Netmæligögn",
        "app.title":                          "Viking Bio – Tækjastillir",
        "app.version":                        "Stillir: %s",
        "status.loading":                     "Sæki stöðu tækis...",
        "status.unavailable.offline":         "Staða er ekki tiltæk: engin Pico-raðtenging er tengd.\nTengdu tæki með USB eða stilltu PICO_SERIAL_PORT til að virkja beina uppsetningu.\nStillirinn keyrir í ótengdum/netsham.",
        "status.unavailable.error":           "Staða er ekki tiltæk: %s",
        "status.wifi.connected":              "tengt",
        "status.wifi.disconnected":           "ekki tengt",
        "status.telemetry.waiting":           "Bíð eftir mæligögnum...",
        "status.telemetry.unavailable":       "Bíð eftir mæligögnum...\nÞjónninn er ekki tengdur við virkan mæligagnastraum.",
        "status.telemetry.empty":             "Bíð eftir mæligögnum...\nEngin gögn hafa borist enn.",
        "status.live_telemetry_unavailable":  "Lifandi mæligögn eru ekki tiltæk; stillirinn er ekki tengdur við virkan mæligagnastraum.",
        "status.live_telemetry_empty":        "  Bíð eftir mæligögnum... Engin gögn hafa borist enn.",
        "status.last_contact":                "Síðasta uppfærsla",
        "button.show_status":                 "Sýna stöðu tækis",
        "button.configure_wifi":              "Stilla Wi‑Fi",
        "button.set_country":                 "Stilla landskóða",
        "button.set_server":                  "Stilla vistfang og gátt þjóns",
        "button.set_webhook":                 "Stilla webhook-slóð",
        "button.provision_key":               "Úthluta mæligagnalykil",
        "button.clear_credentials":           "Hreinsa öll auðkenni",
        "button.close":                       "Loka",
        "dialog.save":                        "Vista",
        "dialog.cancel":                      "Hætta við",
        "dialog.set":                         "Stilla",
        "dialog.done":                        "Lokið",
        "dialog.provisioned":                 "Úthlutað",
        "dialog.wifi.title":                  "Stilla Wi‑Fi",
        "dialog.wifi.saved_title":            "Wi‑Fi stillt",
        "dialog.wifi.saved_body":             "Upplýsingar voru vistaðar. Tækið endurræsist.",
        "dialog.country.title":               "Stilla Wi‑Fi-landskóða",
        "dialog.server.title":                "Stilla þjón",
        "dialog.webhook.title":               "Stilla webhook-slóð",
        "dialog.clear.title":                 "Hreinsa auðkenni",
        "dialog.clear.body":                  "Þetta eyðir öllum vistuðum auðkennum og endurræsir tækið.\nErtu viss?",
        "form.ssid":                          "SSID",
        "form.password":                      "Lykilorð",
        "form.server":                        "IP/heiti þjóns",
        "form.port":                          "Gátt",
        "form.webhook":                       "Webhook-slóð",
        "form.region":                        "Wi‑Fi-svæði",
        "placeholder.ssid":                   "MittNet",
        "placeholder.password":               "lykilorð",
        "placeholder.server":                 "192.168.1.10 eða fd00::1",
        "placeholder.webhook":                "https://hooks.example.com/leynilegt",
        "error.blank_ssid":                   "SSID má ekki vera tómt",
        "error.blank_server":                 "vistfang þjóns má ekki vera tómt",
        "error.invalid_webhook":              "webhook-slóð verður að byrja á http:// eða https://",
        "error.reading_status":               "Villa við lestur stöðu: %s",
        "error.generating_key":               "Villa við gerð tækjalykils: %s",
        "error.storing_key":                  "Villa við vistun tækjalykils: %s",
        "error.device_id_missing":            "Tækjaauðkenni vantar í STATUS-úttak.",
        "error.unknown_option":               "Óþekkt val.",
        "menu.option1":                       "Sýna stöðu tækis",
        "menu.option2":                       "Stilla Wi‑Fi (SSID + lykilorð)",
        "menu.option3":                       "Stilla Wi‑Fi-landskóða",
        "menu.option4":                       "Stilla vistfang og gátt þjóns",
        "menu.option5":                       "Stilla webhook-slóð",
        "menu.option6":                       "Úthluta mæligagnalykil",
        "menu.option7":                       "Hreinsa öll auðkenni",
        "menu.option8":                       "Sýna lifandi mæligögn",
        "menu.option0":                       "Hætta",
        "menu.choice":                        "Val: ",
        "tui.device_status":                  "Staða tækis:",
        "tui.live_telemetry":                 "Lifandi mæligögn brennara:",
        "tui.cancelled":                      "Hætt við.",
        "tui.credentials_saved":              "Upplýsingar voru vistaðar. Tækið endurræsist.",
        "tui.country_prompt":                 "Landskóði (t.d. SE, US): ",
        "tui.invalid_country":                "Ógildur landskóði (verður að vera 2 stafir).",
        "tui.server_prompt":                  "IP/heiti þjóns: ",
        "tui.server_port_prompt":             "Gátt þjóns [9000]: ",
        "tui.webhook_prompt":                 "Webhook-slóð (http:// eða https://): ",
        "tui.invalid_webhook":                "Webhook-slóð verður að byrja á http:// eða https://.",
        "tui.telemetry_provisioned":          "Mæligagnalykli var úthlutað fyrir %s.",
        "tui.clear_confirm":                  "Skrifaðu YES til að staðfesta hreinsun allra auðkenna: ",
        "tui.credentials_cleared":            "Auðkenni voru hreinsuð. Tækið endurræsist.",
        "tui.bye":                            "Bless!",
        "telemetry.title":                    "Netmæligögn",
        "telemetry.label":                    "Lifandi mæligögn brennara",
        "telemetry.error.notification_title": "Viking Bio – villa í brennara",
        "telemetry.error.notification_body":  "Nýr villukóði frá brennara: %.0f",
        "region.worldwide":                   "Alþjóðlegt",
    },
}

type provisioningLocalizer struct {
    language string
}

func newProvisioningLocalizer() provisioningLocalizer {
    return provisioningLocalizer{language: detectProvisioningLanguage()}
}

func detectProvisioningLanguage() string {
    candidates := []string{
        os.Getenv("CONFIGURATOR_LANGUAGE"),
        os.Getenv("LC_ALL"),
        os.Getenv("LC_MESSAGES"),
        os.Getenv("LANG"),
    }
    for _, candidate := range candidates {
        if normalized := normalizeProvisioningLanguage(candidate); normalized != "" {
            return normalized
        }
    }
    return defaultProvisioningLanguage
}

func normalizeProvisioningLanguage(value string) string {
    value = strings.TrimSpace(value)
    if value == "" {
        return ""
    }
    value = strings.ReplaceAll(value, "_", "-")
    value = strings.TrimSuffix(value, ".UTF-8")
    value = strings.TrimSuffix(value, ".utf8")
    if value == "C" || value == "POSIX" {
        return defaultProvisioningLanguage
    }

    parsed, err := language.Parse(value)
    if err == nil {
        base, _ := parsed.Base()
        switch base.String() {
        case "en", "sv", "fi", "da", "is":
            return base.String()
        case "no", "nb", "nn":
            return "no"
        }
    }

    lower := strings.ToLower(value)
    switch {
    case strings.HasPrefix(lower, "en"):
        return "en"
    case strings.HasPrefix(lower, "sv"):
        return "sv"
    case strings.HasPrefix(lower, "no"), strings.HasPrefix(lower, "nb"), strings.HasPrefix(lower, "nn"):
        return "no"
    case strings.HasPrefix(lower, "fi"):
        return "fi"
    case strings.HasPrefix(lower, "da"):
        return "da"
    case strings.HasPrefix(lower, "is"):
        return "is"
    default:
        return defaultProvisioningLanguage
    }
}

func (l provisioningLocalizer) Text(key string, args ...any) string {
    if catalog, ok := provisioningMessages[l.language]; ok {
        if text, found := catalog[key]; found {
            if len(args) > 0 {
                return fmt.Sprintf(text, args...)
            }
            return text
        }
    }
    text := provisioningMessages[defaultProvisioningLanguage][key]
    if len(args) > 0 {
        return fmt.Sprintf(text, args...)
    }
    return text
}

func (l provisioningLocalizer) Language() string {
    return l.language
}

func (l provisioningLocalizer) SupportedLanguages() []string {
    languages := make([]string, 0, len(supportedProvisioningLanguages))
    languages = append(languages, supportedProvisioningLanguages...)
    return languages
}

func (l provisioningLocalizer) LanguageName(code string) string {
    if name, ok := supportedProvisioningLanguageNames[code]; ok {
        return name
    }
    return supportedProvisioningLanguageNames[defaultProvisioningLanguage]
}

func (l provisioningLocalizer) languageTag() language.Tag {
    switch l.language {
    case "sv":
        return language.Swedish
    case "no":
        return language.Norwegian
    case "fi":
        return language.Finnish
    case "da":
        return language.Danish
    case "is":
        return language.Icelandic
    default:
        return language.English
    }
}

func (l provisioningLocalizer) regionLabel(countryCode string) string {
    countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
    if countryCode == "" || countryCode == "XX" {
        return l.Text("region.worldwide") + " (XX)"
    }

    region, err := language.ParseRegion(countryCode)
    if err != nil {
        return l.Text("region.worldwide") + " (XX)"
    }

    var name string
    switch l.language {
    case "sv":
        name = display.Swedish.Regions().Name(region)
    case "no":
        name = display.Norwegian.Regions().Name(region)
    case "fi":
        name = display.Finnish.Regions().Name(region)
    case "da":
        name = display.Danish.Regions().Name(region)
    case "is":
        name = display.Icelandic.Regions().Name(region)
    default:
        name = display.English.Regions().Name(region)
    }
    if strings.TrimSpace(name) == "" {
        name = display.English.Regions().Name(region)
    }
    if strings.TrimSpace(name) == "" {
        name = countryCode
    }
    return fmt.Sprintf("%s (%s)", name, countryCode)
}
