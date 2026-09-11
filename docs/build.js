/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

// Static docs generator for the English and Swedish landing pages.
// The generated HTML files in docs/en/, docs/sv/, and docs/index.html are committed build artifacts.
// Regenerate from the repo root with: node docs/build.js

const fs = require('fs');
const path = require('path');

const root = __dirname;
const englishDir = path.join(root, 'en');
const swedishDir = path.join(root, 'sv');

const pages = {
  en: {
    lang: 'en',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio integration for monitoring and managing pellet burner telemetry with a Pico-based bridge and local configurator.',
    nav: ['Overview', 'Features', 'Architecture', 'Project'],
    heroEyebrow: 'Pellet burner monitoring',
    heroTitle: 'Turn a Viking Bio 20 into a connected, observable heating system',
    heroLead:
      'This project brings together a Raspberry Pi Pico bridge, signed telemetry, and a local Go configurator to monitor burner health, track operational state, and simplify setup on a home or property network.',
    showcaseTitle: 'Local setup, from the desktop',
    showcaseConfiguratorAlt:
      'Viking Bio configurator GUI showing device status, Wi‑Fi configuration, and local setup actions.',
    showcaseConfiguratorCaption:
      'The local configurator GUI keeps burner setup, provisioning, and status checks in one desktop workflow.',
    showcasePicoAlt: 'Raspberry Pi Pico 2 W board illustration for the local burner bridge.',
    showcasePicoCaption:
      'The Pico 2 W acts as the small, low-power bridge between the burner and the local runtime.',
    ctaExplore: 'Explore the project',
    ctaSource: 'View source',
    sourceAria: 'View source on GitHub (opens in new tab)',
    footerGitHubAria: 'Viking Bio project on GitHub (opens in new tab)',
    panelLabel: 'Telemetry flow',
    panelConfigurator: 'Headless Go runtime',
    panelItem1: 'UART capture from burner output',
    panelItem2: 'Signed TCP stream to local runtime',
    panelItem3: 'Local API + USB provisioning flow',
    overviewEyebrow: 'Overview',
    overviewTitle: 'Built for reliability, visibility, and local ownership',
    cardBridgeTitle: 'Reliable bridge',
    cardBridgeBody:
      'A Pico W / Pico 2 W firmware layer reads the burner UART stream, stores Wi‑Fi and server configuration locally, and forwards signed telemetry over a persistent TCP connection.',
    cardControlTitle: 'Local control plane',
    cardControlBody:
      'The Go configurator manages onboarding, bridge status, and the local runtime without creating a dependency on a remote service or hosted web app.',
    cardInsightTitle: 'Operational insight',
    cardInsightBody:
      'The project is designed to surface burner state and fault information through a local API and a separate browser push app, without serving a dashboard at the root.',
    featuresEyebrow: 'Features',
    featuresTitle: 'Everything needed to make a burner smarter without losing control',
    featureTelemetryTitle: 'Signed telemetry',
    featureTelemetryBody:
      'Each message is authenticated with a device key so the local server can verify incoming burner data.',
    featureUSBTitle: 'USB provisioning',
    featureUSBBody:
      'Bridge setup can happen over serial with a GUI or terminal-based configurator, making installation straightforward.',
    featureNetworkTitle: 'Headless local runtime',
    featureNetworkBody:
      'The runtime is built around a local device-first model: the Go service exposes APIs and USB setup, while browser notifications are handled by the separate push-pwa app.',
    featureMDNSTitle: 'mDNS discovery',
    featureMDNSBody:
      'The bridge listens for mDNS announcements from the configurator, allowing automatic service discovery on a home network without manual configuration.',
    featureStateTitle: 'Persistent state',
    featureStateBody:
      'Wi‑Fi credentials, server settings, and per-device identity are kept in local flash-backed storage.',
    featureHardwareTitle: 'Open hardware path',
    featureHardwareBody:
      'The repo is intentionally transparent: firmware, protocol logic, runtime, and configuration tooling live together.',
    architectureEyebrow: 'Architecture',
    architectureTitle: 'Simple layered flow, clear ownership, and a local-first runtime',
    architectureBody:
      'The system separates the hardware-facing bridge from the headless Go runtime and the separate browser-push app. The Pico reads burner data and streams signed telemetry to a Go process on the same trusted local network. That Go process exposes the API and USB configuration flow while the bridge stays focused on measurement, ingest, and alert delivery.',
    stack1: 'Burner serial data',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signed TCP ingest',
    stack4: 'Headless Go runtime + local APIs',
    stack5: 'push-pwa browser notifications',
    projectEyebrow: 'Project',
    projectTitle: 'Built for owners, integrators, and makers who want a practical burner monitor',
    projectBody1:
      'This repository is a complete integration project for the Viking Bio 20 pellet burner: firmware, protocol parsing, local runtime, and a separate browser push app for operator alerts. It is designed to be understandable, extensible, and easy to run on a small local device or home network.',
    projectBody2:
      'The focus is honest operational control: keep data local, verify the device at the edge, and provide a reliable configuration flow without depending on a hosted product or cloud backend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  sv: {
    lang: 'sv',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio-integration för att övervaka och hantera telemetri från pelletsbrännare med en Pico-baserad brygga och lokal konfigurator.',
    nav: ['Översikt', 'Funktioner', 'Arkitektur', 'Projekt'],
    heroEyebrow: 'Pellettbrännarmonitorering',
    heroTitle: 'Gör en Viking Bio 20 till ett uppkopplat, observerbart värmesystem',
    heroLead:
      'Det här projektet kombinerar en Raspberry Pi Pico-brygga, signerad telemetri och en lokal Go-konfigurator för att övervaka brännarens hälsa, följa driftstatus och förenkla installation i hemmet eller på fastigheten.',
    showcaseTitle: 'Lokal installation från skrivbordet',
    showcaseConfiguratorAlt:
      'Viking Bio-konfigurationsgränssnitt som visar enhetsstatus, Wi‑Fi-konfiguration och lokala inställningar.',
    showcaseConfiguratorCaption:
      'Det lokala konfigurationsgränssnittet samlar uppstart, provisionering och statuskontroll i ett skrivbordsflöde.',
    showcasePicoAlt: 'Illustration av Raspberry Pi Pico 2 W för den lokala brännar-bryggan.',
    showcasePicoCaption:
      'Pico 2 W fungerar som den lilla, energieffektiva bryggan mellan brännaren och den lokala runtime:n.',
    ctaExplore: 'Utforska projektet',
    ctaSource: 'Visa källkod',
    sourceAria: 'Visa källkod på GitHub (öppnas i ny flik)',
    footerGitHubAria: 'Viking Bio-projekt på GitHub (öppnas i ny flik)',
    panelLabel: 'Telemetriflöde',
    panelConfigurator: 'Headless Go-runtime',
    panelItem1: 'UART-avläsning från brännaren',
    panelItem2: 'Signerad TCP-ström till lokal runtime',
    panelItem3: 'Lokalt API + USB-konfigurationsflöde',
    overviewEyebrow: 'Översikt',
    overviewTitle: 'Byggt för tillförlitlighet, överblick och lokalt ägarskap',
    cardBridgeTitle: 'Tillförlitlig brygga',
    cardBridgeBody:
      'Ett Pico W / Pico 2 W-firmware läser brännarens UART-flöde, lagrar Wi‑Fi- och serverinställningar lokalt och vidarebefordrar signerad telemetri via en stabil TCP-anslutning.',
    cardControlTitle: 'Lokal styrplan',
    cardControlBody:
      'Go-konfiguratorn sköter onboarding, bryggstatus och lokal runtime utan att förlita sig på en extern tjänst eller molnapp.',
    cardInsightTitle: 'Driftsinsikt',
    cardInsightBody:
      'Projektet visar brännarens tillstånd och fel via ett lokalt API och en separat browser-push-app, utan att exponera en dashboard på roten.',
    featuresEyebrow: 'Funktioner',
    featuresTitle: 'Allt som behövs för att göra en brännare smartare utan att förlora kontrollen',
    featureTelemetryTitle: 'Signerad telemetri',
    featureTelemetryBody:
      'Varje meddelande autentiseras med en enhetsnyckel så att den lokala servern kan verifiera inkommande data.',
    featureUSBTitle: 'USB-installation',
    featureUSBBody:
      'Bryggkonfiguration kan ske över seriell port med GUI eller terminalbaserad konfigurator, vilket gör installationen enkel.',
    featureNetworkTitle: 'Headless lokal runtime',
    featureNetworkBody:
      'Runtime är byggt kring en lokal, enhetscentrerad modell: Go-tjänsten exponeras via API och USB-konfiguration, medan browser-notifieringar hanteras av den separata push-pwa-appen.',
    featureMDNSTitle: 'mDNS-upptäckt',
    featureMDNSBody:
      'Bryggan lyssnar efter mDNS-meddelanden från konfiguratorn, vilket möjliggör automatisk tjänsteupptäckt i ett hemnät utan manuell konfiguration.',
    featureStateTitle: 'Beständig status',
    featureStateBody:
      'Wi‑Fi-uppgifter, serverinställningar och per-enhetsidentifiering sparas i lokal flash-baserad lagring.',
    featureHardwareTitle: 'Öppen hårdvaruväg',
    featureHardwareBody:
      'Repo:t är avsiktligt transparent: firmware, protokollparsering, runtime och konfigurationsverktyg finns samlat.',
    architectureEyebrow: 'Arkitektur',
    architectureTitle: 'Enkelt lagerflöde, tydlig ansvarsfördelning och lokal-first design',
    architectureBody:
      'Systemet separerar hårdvarunära bryggan från den headless Go-runtimen och den separata browser-push-appen. Pico läser brännardata och strömmar signerad telemetri till en Go-process i samma lokala nätverk. Den processen exponeras via API och USB-konfigurationsflöde medan bryggan fokuserar på mätning, ingest och varningstillförsel.',
    stack1: 'Seriedata från brännaren',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signerad TCP-ingest',
    stack4: 'Headless Go-runtime + lokala API:er',
    stack5: 'push-pwa browser-notifieringar',
    projectEyebrow: 'Projekt',
    projectTitle: 'Byggt för ägare, installatörer och skapare som vill ha en praktisk brännarmonitor',
    projectBody1:
      'Det här repo:t är ett komplett integrationsprojekt för Viking Bio 20-pelletbrännaren: firmware, protokollanalys, lokal runtime och en separat browser-push-app för operatörsvarningar. Det är designat för att vara lätt att förstå, utöka och köra på liten lokal utrustning i hemmet.',
    projectBody2:
      'Fokus ligger på ärlig driftkontroll: håll data lokalt, verifiera enheten i kanten och erbjuda ett pålitligt konfigurationsflöde utan att vara beroende av en hostad produkt eller molnbackend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  no: {
    lang: 'no',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio-integrasjon for overvåkning og styring av pelletsbrenseltelemetri med en Pico-baseret bro og lokal konfigurasjon.',
    nav: ['Oversikt', 'Funksjoner', 'Arkitektur', 'Prosjekt'],
    heroEyebrow: 'Pelletsbrenselovervåking',
    heroTitle: 'Gjør en Viking Bio 20 til et koblet, observerbart varmesystem',
    heroLead:
      'Dette prosjektet kombinerer en Raspberry Pi Pico-bro, signert telemetri og en lokal Go-konfigurasjon for å overvåke brennerens tilstand, spore driftsstatus og forenkle oppsett på hjemmenettverk eller eiendom.',
    showcaseTitle: 'Lokal installasjon fra skrivebordet',
    showcaseConfiguratorAlt: 'Viking Bio-konfigurasjon som viser enhetsstatus, Wi‑Fi-konfigurasjon og lokale innstillinger.',
    showcaseConfiguratorCaption: 'Den lokale konfigurasjonsappen holder oppsett, provisionering og statuskontroller i samme skrivebordsflyt.',
    showcasePicoAlt: 'Illustrasjon av Raspberry Pi Pico 2 W for den lokale brennerbroen.',
    showcasePicoCaption: 'Pico 2 W fungerer som den små, energieffektive broen mellom brenneren og den lokale runtime-en.',
    ctaExplore: 'Utforsk prosjektet',
    ctaSource: 'Vis kildekode',
    sourceAria: 'Vis kildekode på GitHub (åpner i ny fane)',
    footerGitHubAria: 'Viking Bio-prosjekt på GitHub (åpner i ny fane)',
    panelLabel: 'Telemetri flyt',
    panelConfigurator: 'Headless Go-runtime',
    panelItem1: 'UART-opptak fra brennerutgang',
    panelItem2: 'Signert TCP-strøm til lokal runtime',
    panelItem3: 'Lokal API + USB-oppsett',
    overviewEyebrow: 'Oversikt',
    overviewTitle: 'Bygget for pålitelighet, synlighet og lokalt eierskap',
    cardBridgeTitle: 'Pålitelig bro',
    cardBridgeBody: 'En Pico W / Pico 2 W firmware leser brennerens UART-strøm, lagrer Wi‑Fi- og tjenerkonfigurasjon lokalt og videresender signert telemetri over en stabil TCP-tilkobling.',
    cardControlTitle: 'Lokal kontrollplan',
    cardControlBody: 'Go-konfigurasjonen håndterer onboarding, brostatus og lokal runtime uten å være avhengig av en ekstern tjeneste eller nettside.',
    cardInsightTitle: 'Driftsinnsikt',
    cardInsightBody: 'Prosjektet er designet for å vise brennerstatus og feil via et lokalt API og en separat browser-push-app uten å tilby en dashboard på rotnivå.',
    featuresEyebrow: 'Funksjoner',
    featuresTitle: 'Alt som trengs for å gjøre en brenner smartere uten å miste kontrollen',
    featureTelemetryTitle: 'Signert telemetri',
    featureTelemetryBody: 'Hver melding autentiseres med en enhetsnøkkel, slik at den lokale tjeneren kan verifisere innkommende data.',
    featureUSBTitle: 'USB-provisionering',
    featureUSBBody: 'Brooppsettet kan skje over serielport med GUI eller terminalbasert konfigurasjon, som gjør installasjonen enkel.',
    featureNetworkTitle: 'Headless lokal runtime',
    featureNetworkBody: 'Runtime er bygget rundt en lokal, enhetsorientert modell: Go-tjenesten eksponerer API-er og USB-oppsett, mens browser-varsler håndteres av den separate push-pwa-appen.',
    featureMDNSTitle: 'mDNS-oppdagelse',
    featureMDNSBody: 'Broen lytter etter mDNS-varsler fra konfigurasjonen, som muliggjør automatisk tjenesteoppdagelse på hjemmenettverk uten manuell konfigurasjon.',
    featureStateTitle: 'Bestående tilstand',
    featureStateBody: 'Wi‑Fi-opplysninger, tjenerinnstillinger og enhetsidentitet lagres lokalt i flash-basert lagring.',
    featureHardwareTitle: 'Åpen maskinva',
    featureHardwareBody: 'Repoet er bevisst åpent: firmware, protokollparsing, runtime og konfigurasjonsverktøy lever sammen.',
    architectureEyebrow: 'Arkitektur',
    architectureTitle: 'Enkel lagdelt flyt, tydelig eierskap og lokal først',
    architectureBody: 'Systemet skiller den maskinvendte broen fra den headless Go-runtime-en og den separate browser-push-appen. Picoen leser brennerdata og strømmer signert telemetri til en Go-prosess på det samme lokale nettverket. Denne prosessen eksponerer API og USB-konfigurasjon, mens broen fokuserer på måling, innsamling og varsling.',
    stack1: 'Seriedata fra brenneren',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signert TCP-ingest',
    stack4: 'Headless Go-runtime + lokale API-er',
    stack5: 'push-pwa browser-varsler',
    projectEyebrow: 'Prosjekt',
    projectTitle: 'Bygget for eiere, installatører og skapere som vil ha en praktisk brennermonitor',
    projectBody1: 'Dette repoet er et komplett integrasjonsprosjekt for Viking Bio 20 pelletsbrenneren: firmware, protokollanalyse, lokal runtime og en separat browser-push-app for operatørvarsler. Det er designet for å være forståelig, utvidbart og enkelt å kjøre på liten lokal utstyr eller hjemmenettverk.',
    projectBody2: 'Fokuset er på ærlig operasjonell kontroll: hold data lokalt, verifiser enheten i kanten og tilby et pålitelig konfigurasjonsflyt uten å være avhengig av en hostet produkt eller cloud-backend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  fi: {
    lang: 'fi',
    title: 'Viking Bio Integration',
    metaDescription: 'Viking Bio -integraatio pellettipolttimen telemetrian seurantaan ja hallintaan Pico-pohjaisella sillalla ja paikallisella konfiguraattorilla.',
    nav: ['Yleiskatsaus', 'Ominaisuudet', 'Arkkitehtuuri', 'Projekti'],
    heroEyebrow: 'Pellettipolttimen seuranta',
    heroTitle: 'Tee Viking Bio 20:stä kytketty, havainnoitava lämmitysjärjestelmä',
    heroLead: 'Tämä projekti yhdistää Raspberry Pi Pico -sillan, allekirjoitetun telemetrian ja paikallisen Go-konfiguraattorin, jotta polttimen terveyttä, käyttötilaa ja asennusta voidaan hallita kotiverkossa tai kiinteistössä.',
    showcaseTitle: 'Paikallinen asennus työpöydältä',
    showcaseConfiguratorAlt: 'Viking Bio -konfiguraattori, joka näyttää laitteen tilan, Wi‑Fi-asetukset ja paikalliset toiminnot.',
    showcaseConfiguratorCaption: 'Paikallinen konfiguraattori pitää asennuksen, provisionoinnin ja tilan tarkastelun yhdessä työpöytäytössä.',
    showcasePicoAlt: 'Raspberry Pi Pico 2 W -kaavio paikalliselle polttimen sillalle.',
    showcasePicoCaption: 'Pico 2 W toimii pienenä, energiatehokkaana sillana polttimen ja paikallisen ajon välillä.',
    ctaExplore: 'Tutustu projektiin',
    ctaSource: 'Näytä lähdekoodi',
    sourceAria: 'Näytä lähdekoodi GitHubissa (avautuu uuteen välilehteen)',
    footerGitHubAria: 'Viking Bio -projekti GitHubissa (avautuu uuteen välilehteen)',
    panelLabel: 'Telemetriajakot',
    panelConfigurator: 'Headless Go-runtime',
    panelItem1: 'UART-keruu polttimelta',
    panelItem2: 'Allekirjoitettu TCP-virta paikalliseen runtimeen',
    panelItem3: 'Paikallinen API + USB-provisionointi',
    overviewEyebrow: 'Yleiskatsaus',
    overviewTitle: 'Rakennettu luotettavuuteen, näkyvyyteen ja paikalliseen omistajuuteen',
    cardBridgeTitle: 'Luotettava silta',
    cardBridgeBody: 'Pico W / Pico 2 W -laite lukee polttimen UART-virran, tallentaa Wi‑Fi- ja palvelinasetukset paikallisesti ja välittää allekirjoitettua telemetriaa vakaalla TCP-yhteydellä.',
    cardControlTitle: 'Paikallinen ohjaustaso',
    cardControlBody: 'Go-konfiguraattori hallitsee käyttöönottoa, sillan tilaa ja paikallista runtimea ilman riippuvuutta etäpalvelusta tai hosted-web-sovelluksesta.',
    cardInsightTitle: 'Toiminta-aistimus',
    cardInsightBody: 'Projekti on suunniteltu näyttämään polttimen tila ja virheet paikallisen API:n ja erillisen selaimella toimivan push-sovelluksen kautta ilman juuritasolla sijaitsevaa dashboardia.',
    featuresEyebrow: 'Ominaisuudet',
    featuresTitle: 'Kaikki, mitä tarvitaan tekemään polttimesta fiksumpi ilman hallinnan menetystä',
    featureTelemetryTitle: 'Allekirjoitettu telemetria',
    featureTelemetryBody: 'Jokainen viesti on autentisoitu laiteavaimella, jotta paikallinen palvelin voi vahvistaa saapuvan datan.',
    featureUSBTitle: 'USB-provisionointi',
    featureUSBBody: 'Silta voidaan konfiguroida sarjaportin kautta GUI:lla tai terminaalipohjaisella konfiguraattorilla, mikä tekee asennuksesta yksinkertaisen.',
    featureNetworkTitle: 'Headless paikallinen runtime',
    featureNetworkBody: 'Runtime on rakennettu paikallisen laitteen ympärille: Go-palvelu tarjoaa API:t ja USB-asetukset, kun taas selaimen ilmoitukset käsitellään erillisessä push-pwa-sovelluksessa.',
    featureMDNSTitle: 'mDNS-löytö',
    featureMDNSBody: 'Silta kuuntelee konfiguraattorin mDNS-ilmoituksia, mahdollistaen automaattisen palvelun löytämisen kotiverkossa ilman manuaalista konfigurointia.',
    featureStateTitle: 'Pysyvä tila',
    featureStateBody: 'Wi‑Fi-kirjaukset, palvelinasetukset ja laite-identiteetti tallennetaan paikalliseen flash-pohjaiseen tallennustilaan.',
    featureHardwareTitle: 'Avoin laitteisto-polku',
    featureHardwareBody: 'Repo on tarkoituksellisesti läpinäkyvä: firmware, protokollalogiikka, runtime ja konfiguraatiotyökalut elävät yhdessä.',
    architectureEyebrow: 'Arkkitehtuuri',
    architectureTitle: 'Yksinkertainen kerroksinen virtaus, selkeä omistajuus ja paikallisuus',
    architectureBody: 'Järjestelmä erottaa laitteistosillan päällimmäisestä Go-runtimesta ja erillisestä browser-push-sovelluksesta. Pico lukee polttimen dataa ja lähettää allekirjoitettua telemetriaa Go-prosessiin samalla luotettavassa paikallisessa verkossa. Tämä prosessi tarjoaa API:n ja USB-konfiguraation, kun taas silta keskittyy mittaukseen, ingestiin ja hälytyksiin.',
    stack1: 'Polttimen sarjadata',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Allekirjoitettu TCP-ingest',
    stack4: 'Headless Go-runtime + paikalliset API:t',
    stack5: 'push-pwa-selaimen ilmoitukset',
    projectEyebrow: 'Projekti',
    projectTitle: 'Rakennettu omistajille, integraattoreille ja tekijöille, jotka haluavat käytännöllisen polttimen monitorin',
    projectBody1: 'Tämä repo on täydellinen integraatioprojekti Viking Bio 20 -pellettipolttimelle: firmware, protokollan käsittely, paikallinen runtime ja erillinen browser-push-sovellus operaattorihälytyksille. Se on suunniteltu ymmärrettäväksi, laajennettavaksi ja helposti ajettavaksi pienellä paikallisella laitteella tai kotiverkossa.',
    projectBody2: 'Painopiste on rehellinen operatiivinen hallinta: pidä data paikallisesti, varmista laite reunassa ja tarjoa luotettava konfiguraatiovirta ilman riippuvuutta isännöidyltä tuotteelta tai cloud-backendilta.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  da: {
    lang: 'da',
    title: 'Viking Bio Integration',
    metaDescription: 'Viking Bio-integration til overvågning og styring af pelletbrændertelemetri med en Pico-baseret bro og lokal konfiguration.',
    nav: ['Oversigt', 'Funktioner', 'Arkitektur', 'Projekt'],
    heroEyebrow: 'Pelletbrænder-overvågning',
    heroTitle: 'Gør en Viking Bio 20 til et forbundet og observerbart varmesystem',
    heroLead: 'Dette projekt kombinerer en Raspberry Pi Pico-bro, signeret telemetri og en lokal Go-konfiguration for at overvåge brænderens tilstand, spore driftsstatus og forenkle opsætning på hjemmenetværk eller ejendom.',
    showcaseTitle: 'Lokal opsætning fra skrivebordet',
    showcaseConfiguratorAlt: 'Viking Bio-konfigurationsgrænseflade, der viser enhedsstatus, Wi‑Fi-konfiguration og lokale handlinger.',
    showcaseConfiguratorCaption: 'Den lokale konfigurationsgrænseflade holder opsætning, provisionering og statuskontrol i samme skrivebordsflow.',
    showcasePicoAlt: 'Illustration af Raspberry Pi Pico 2 W til den lokale brænderbro.',
    showcasePicoCaption: 'Pico 2 W fungerer som den lille, energieffektive bro mellem brænderen og den lokale runtime.',
    ctaExplore: 'Udforsk projektet',
    ctaSource: 'Vis kildekode',
    sourceAria: 'Vis kildekode på GitHub (åbner i ny fane)',
    footerGitHubAria: 'Viking Bio-projekt på GitHub (åbner i ny fane)',
    panelLabel: 'Telemetriflow',
    panelConfigurator: 'Headless Go-runtime',
    panelItem1: 'UART-indsamling fra brænderens udgang',
    panelItem2: 'Signeret TCP-strøm til lokal runtime',
    panelItem3: 'Lokal API + USB-provisionering',
    overviewEyebrow: 'Oversigt',
    overviewTitle: 'Bygget til pålidelighed, synlighed og lokalt ejerskab',
    cardBridgeTitle: 'Pålidelig bro',
    cardBridgeBody: 'En Pico W / Pico 2 W firmware læser brænderens UART-strøm, gemmer Wi‑Fi og serverindstillinger lokalt og videresender signeret telemetri over en stabil TCP-forbindelse.',
    cardControlTitle: 'Lokal kontrolplan',
    cardControlBody: 'Go-konfigurationen styrer onboarding, brostatus og lokal runtime uden at afhænge af en ekstern service eller hosted webapp.',
    cardInsightTitle: 'Driftsindsigt',
    cardInsightBody: 'Projektet er designet til at vise brænderstatus og fejl via et lokalt API og en separat browser-push-app uden at eksponere en dashboard i roden.',
    featuresEyebrow: 'Funktioner',
    featuresTitle: 'Alt, hvad der skal til for at gøre en brænder smartere uden at miste kontrollen',
    featureTelemetryTitle: 'Signeret telemetri',
    featureTelemetryBody: 'Hver meddelelse autentificeres med en enhedsnøgle, så den lokale server kan verificere indkommende data.',
    featureUSBTitle: 'USB-provisionering',
    featureUSBBody: 'Broopsætning kan ske over serielport med GUI eller terminalbaseret konfiguration, hvilket gør installationen enkel.',
    featureNetworkTitle: 'Headless lokal runtime',
    featureNetworkBody: 'Runtime er bygget omkring en lokal, enhedscentreret model: Go-tjenesten eksponerer API-er og USB-oppsætning, mens browsermeddelelser håndteres af den separate push-pwa-app.',
    featureMDNSTitle: 'mDNS-opdagelse',
    featureMDNSBody: 'Broen lytter efter mDNS-meddelelser fra konfigurationsprogrammet, hvilket muliggør automatisk tjenesteopdagelse på hjemmenetværk uden manuel konfiguration.',
    featureStateTitle: 'Vedvarende tilstand',
    featureStateBody: 'Wi‑Fi-oplysninger, serverindstillinger og enhedsidentitet gemmes lokalt i flash-baseret lagring.',
    featureHardwareTitle: 'Åbent hardwareforløb',
    featureHardwareBody: 'Repoet er bevidst gennemsigtigt: firmware, protokolbehandling, runtime og konfigurationsværktøjer findes sammen.',
    architectureEyebrow: 'Arkitektur',
    architectureTitle: 'Simpelt lagdelt flow, tydelig ejerskab og lokal-first design',
    architectureBody: 'Systemet adskiller hardware-tilknyttede broen fra headless Go-runtimeen og den separate browser-push-app. Pico læser brænderdata og sender signeret telemetri til en Go-proces på samme betroede lokale netværk. Den proces eksponerer API og USB-konfigurationsflow, mens broen fokuserer på måling, ingest og varselstilførsel.',
    stack1: 'Seriedata fra brænderen',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signeret TCP-ingest',
    stack4: 'Headless Go-runtime + lokale API-er',
    stack5: 'push-pwa browser-varsel',
    projectEyebrow: 'Projekt',
    projectTitle: 'Bygget til ejere, installatører og skabere, der vil have en praktisk brændermonitor',
    projectBody1: 'Dette repo er et komplet integrationsprojekt til Viking Bio 20 pelletbrænderen: firmware, protokolanalyse, lokal runtime og en separat browser-push-app til operatøralarmer. Det er designet til at være forståeligt, udvideligt og nemt at køre på lille lokal hardware eller hjemmenetværk.',
    projectBody2: 'Fokus er ærlig driftskontrol: hold data lokalt, verificér enheden i kanten og tilby et pålideligt konfigurationsflow uden at være afhængig af et hostet produkt eller cloud-backend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  is: {
    lang: 'is',
    title: 'Viking Bio Integration',
    metaDescription: 'Viking Bio-integration fyrir eftirlit og stjórnun á pelletsbrennaratelemetríu með Pico-undirstaða brú og staðbundinni uppsetningu.',
    nav: ['Yfirlit', 'Eiginleikar', 'Arkitektúr', 'Verkefni'],
    heroEyebrow: 'Eftirlit með pelletsbrennara',
    heroTitle: 'Gerðu Viking Bio 20 að tengdu, sýnilegu hitakerfi',
    heroLead: 'Þetta verkefni sameinar Raspberry Pi Pico-brú, undirrituð telemetría og staðbundna Go-stillingu til að fylgjast með heilbrigði brunans, rekstrarstöðu og einfalda uppsetningu á heimaneti eða fasteign.',
    showcaseTitle: 'Staðbundin uppsetning úr skjáborðinu',
    showcaseConfiguratorAlt: 'Viking Bio stillingarviðmót sem sýnir stöðu tækis, Wi‑Fi-stillingar og staðbundnar aðgerðir.',
    showcaseConfiguratorCaption: 'Staðbundna stillingarviðmótið heldur uppsetningu, þjónustu og stöðuathugunum í sömu skjáborðsleið.',
    showcasePicoAlt: 'Mynd af Raspberry Pi Pico 2 W fyrir staðbundna brennarabrú.',
    showcasePicoCaption: 'Pico 2 W þjónar sem lítil, orkusparandi brú milli brennarans og staðbundnu keyrslunnar.',
    ctaExplore: 'Skoða verkefnið',
    ctaSource: 'Sjá grunnkóða',
    sourceAria: 'Sjá grunnkóða á GitHub (opnast í nýjum flipa)',
    footerGitHubAria: 'Viking Bio-verkefni á GitHub (opnast í nýjum flipa)',
    panelLabel: 'Telemetríuflæði',
    panelConfigurator: 'Headless Go-runtime',
    panelItem1: 'UART-safn frá brennara',
    panelItem2: 'Undirrituð TCP-straumur til staðbundinnar runtime',
    panelItem3: 'Staðbundið API + USB-uppsetning',
    overviewEyebrow: 'Yfirlit',
    overviewTitle: 'Byggt fyrir áreiðanleika, sýnileika og staðbundið eignarhald',
    cardBridgeTitle: 'Áreiðanleg brú',
    cardBridgeBody: 'Pico W / Pico 2 W innviði lesa UART-straum brennarans, geyma Wi‑Fi og netþjónsstillingar staðbundið og senda undirritaða telemetríu yfir stöðugri TCP-tengingu.',
    cardControlTitle: 'Staðbundin stýring',
    cardControlBody: 'Go-stillingin sér um onboarding, brúarstöðu og staðbundna runtime án þess að treysta á fjarlæga þjónustu eða vefforritastöð.',
    cardInsightTitle: 'Rekstrarinsýn',
    cardInsightBody: 'Verkefnið er hannað til að sýna stöðu og villur brennarans í gegnum staðbundið API og aðskilið push-forrit án þess að bjóða upp á dashboard á rótinni.',
    featuresEyebrow: 'Eiginleikar',
    featuresTitle: 'Allt sem þarf til að gera brennara snjallari án þess að tapa stjórn',
    featureTelemetryTitle: 'Undirrituð telemetría',
    featureTelemetryBody: 'Hver skilaboð eru auðkennd með tæki lykli, svo staðbundin þjónn geti staðfest innkomandi gögn.',
    featureUSBTitle: 'USB-uppræting',
    featureUSBBody: 'Brú uppsetning getur farið fram yfir seríusnertingu með GUI eða terminalundirstaða stillingu, sem gerir uppsetningu einfaldari.',
    featureNetworkTitle: 'Headless staðbundin runtime',
    featureNetworkBody: 'Runtime er byggt á staðbundinni, tæki-vænni líkan: Go-þjónustan veitir API og USB-stillingar á meðan vefviðvaranir eru meðhöndlaðar af aðskildum push-pwa forriti.',
    featureMDNSTitle: 'mDNS uppgötvun',
    featureMDNSBody: 'Brúin hlustar eftir mDNS-tilkynningum frá stillingunni og gerir sjálfvirka þjónustuleit á heimaneti án handvirkrar stillingar.',
    featureStateTitle: 'Varanleg staða',
    featureStateBody: 'Wi‑Fi-uppfærslur, netþjónsstillingar og kennitölu tækis eru geymdar á staðbundinni flash-lageri.',
    featureHardwareTitle: 'Opið vélbúnaðarspor',
    featureHardwareBody: 'Repoið er viljandi gagnsætt: firmware, samskiptareglur, runtime og stillingartæki lifa saman.',
    architectureEyebrow: 'Arkitektúr',
    architectureTitle: 'Einfalt lagskipt flæði, skýr eignarhald og staðbundið hönnun',
    architectureBody: 'Kerfið aðskilur vélbúnaðarbrúna frá headless Go-runtime og aðskildum browser-push-forriti. Pico les brennargögn og streymir undirrituð telemetría til Go-ferlis á sama treystanlega staðbundna neti. Þetta ferli veitir API og USB-stillingar á meðan brúin einbeitir sér að mælingum, innflutningi og viðvörunum.',
    stack1: 'Raðgögn brennara',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Undirrituð TCP-ingest',
    stack4: 'Headless Go-runtime + staðbundið API',
    stack5: 'push-pwa vefviðvaranir',
    projectEyebrow: 'Verkefni',
    projectTitle: 'Byggt fyrir eigendur, samþættingaraðila og skapara sem vilja hagnýta brennaravöktun',
    projectBody1: 'Þetta repo er fullkomið samþættingarverkefni fyrir Viking Bio 20 pelletsbrennarann: firmware, samskiptareglur, staðbundin runtime og aðskilið browser-push-forrit fyrir rekstrarviðvaranir. Það er hannað til að vera skiljanlegt, útvíkjanlegt og auðvelt að keyra á litlu staðbundnu tæki eða heimaneti.',
    projectBody2: 'Áhersla er á heiðarlega rekstrarstýringu: halda gögnum staðbundnum, staðfesta tækið á brúninni og bjóða upp á áreiðanlega stillingaleið án þess að treysta á hýst vörur eða skýja-backend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  }
};

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function renderPage(data) {
  const anchors = ['overview', 'features', 'architecture', 'project'];
  const nav = data.nav
    .map((label, index) => {
      const href = `#${anchors[index]}`;
      return `<a href="${href}">${escapeHtml(label)}</a>`;
    })
    .join('\n          ');

  return `<!DOCTYPE html>
<html lang="${data.lang}">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="${escapeHtml(data.metaDescription)}" />
    <title>${escapeHtml(data.title)}</title>
    <link rel="icon" type="image/svg+xml" href="../favicon.svg" />
    <link rel="stylesheet" href="../styles.css" />
  </head>
  <body id="top">
    <header class="topbar">
      <div class="container nav">
        <a class="brand" href="#top" aria-label="Viking Bio home">
          <span class="brand-mark">V</span>
          <span>Viking Bio</span>
        </a>
        <nav class="nav-links" aria-label="Main navigation">
          ${nav}
        </nav>
      </div>
    </header>

    <main>
      <section class="hero">
        <div class="container hero-grid">
          <div>
            <p class="eyebrow">${escapeHtml(data.heroEyebrow)}</p>
            <h1>${escapeHtml(data.heroTitle)}</h1>
            <p class="lead">${escapeHtml(data.heroLead)}</p>
            <div class="cta-row">
              <a class="button primary" href="#overview">${escapeHtml(data.ctaExplore)}</a>
              <a
                class="button secondary"
                href="https://github.com/phieri/viking-bio-pwa"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="${escapeHtml(data.sourceAria)}"
              >
                ${escapeHtml(data.ctaSource)}
              </a>
            </div>
          </div>
          <div class="hero-panel">
            <div class="panel-card">
              <span class="panel-label">${escapeHtml(data.panelLabel)}</span>
              <div class="flow-block">
                <span>Viking Bio 20</span>
                <span class="arrow">→</span>
                <span>Pico W</span>
                <span class="arrow">→</span>
                <span>${escapeHtml(data.panelConfigurator)}</span>
              </div>
              <ul>
                <li>${escapeHtml(data.panelItem1)}</li>
                <li>${escapeHtml(data.panelItem2)}</li>
                <li>${escapeHtml(data.panelItem3)}</li>
              </ul>
            </div>
          </div>
        </div>
      </section>
 
      <section class="section showcase" aria-label="Configurator and hardware overview">
        <div class="container showcase-grid">
          <figure class="media-card placeholder">
            <span>Configurator placeholder</span>
            <figcaption>${escapeHtml(data.showcaseConfiguratorCaption)}</figcaption>
          </figure>
          <figure class="media-card placeholder">
            <span>Pico placeholder</span>
            <figcaption>${escapeHtml(data.showcasePicoCaption)}</figcaption>
          </figure>
        </div>
      </section>
 
      <section id="overview" class="section">
        <div class="container">
          <div class="section-heading">
            <p class="eyebrow">${escapeHtml(data.overviewEyebrow)}</p>
            <h2>${escapeHtml(data.overviewTitle)}</h2>
          </div>
          <div class="cards three-up">
            <article class="info-card">
              <h3>${escapeHtml(data.cardBridgeTitle)}</h3>
              <p>${escapeHtml(data.cardBridgeBody)}</p>
            </article>
            <article class="info-card">
              <h3>${escapeHtml(data.cardControlTitle)}</h3>
              <p>${escapeHtml(data.cardControlBody)}</p>
            </article>
            <article class="info-card">
              <h3>${escapeHtml(data.cardInsightTitle)}</h3>
              <p>${escapeHtml(data.cardInsightBody)}</p>
            </article>
          </div>
        </div>
      </section>

      <section id="features" class="section alt">
        <div class="container">
          <div class="section-heading narrow">
            <p class="eyebrow">${escapeHtml(data.featuresEyebrow)}</p>
            <h2>${escapeHtml(data.featuresTitle)}</h2>
          </div>

          <div class="feature-list">
            <div class="feature-item">
              <h3>${escapeHtml(data.featureTelemetryTitle)}</h3>
              <p>${escapeHtml(data.featureTelemetryBody)}</p>
            </div>
            <div class="feature-item">
              <h3>${escapeHtml(data.featureUSBTitle)}</h3>
              <p>${escapeHtml(data.featureUSBBody)}</p>
            </div>
            <div class="feature-item">
              <h3>${escapeHtml(data.featureNetworkTitle)}</h3>
              <p>${escapeHtml(data.featureNetworkBody)}</p>
            </div>
            <div class="feature-item">
              <h3>${escapeHtml(data.featureMDNSTitle)}</h3>
              <p>${escapeHtml(data.featureMDNSBody)}</p>
            </div>
            <div class="feature-item">
              <h3>${escapeHtml(data.featureStateTitle)}</h3>
              <p>${escapeHtml(data.featureStateBody)}</p>
            </div>
            <div class="feature-item">
              <h3>${escapeHtml(data.featureHardwareTitle)}</h3>
              <p>${escapeHtml(data.featureHardwareBody)}</p>
            </div>
          </div>
        </div>
      </section>

      <section id="architecture" class="section">
        <div class="container architecture-grid">
          <div>
            <p class="eyebrow">${escapeHtml(data.architectureEyebrow)}</p>
            <h2>${escapeHtml(data.architectureTitle)}</h2>
            <p>${escapeHtml(data.architectureBody)}</p>
          </div>
          <div class="stack">
            <div class="stack-item"><span>1</span><span>${escapeHtml(data.stack1)}</span></div>
            <div class="stack-item"><span>2</span><span>${escapeHtml(data.stack2)}</span></div>
            <div class="stack-item"><span>3</span><span>${escapeHtml(data.stack3)}</span></div>
            <div class="stack-item"><span>4</span><span>${escapeHtml(data.stack4)}</span></div>
            <div class="stack-item"><span>5</span><span>${escapeHtml(data.stack5)}</span></div>
          </div>
        </div>
      </section>

      <section id="project" class="section alt" aria-labelledby="project-title">
        <div class="container">
          <div class="project-panel">
            <div>
              <p class="eyebrow">${escapeHtml(data.projectEyebrow)}</p>
              <h2 id="project-title">${escapeHtml(data.projectTitle)}</h2>
            </div>
            <div class="project-copy">
              <p>${escapeHtml(data.projectBody1)}</p>
              <p>${escapeHtml(data.projectBody2)}</p>
            </div>
          </div>
        </div>
      </section>
    </main>

    <footer class="footer">
      <div class="container footer-row">
        <span>${escapeHtml(data.footerBrand)}</span>
        <a href="https://github.com/phieri/viking-bio-pwa" target="_blank" rel="noopener noreferrer" aria-label="${escapeHtml(data.footerGitHubAria)}">${escapeHtml(data.footerGitHub)}</a>
      </div>
    </footer>
  </body>
</html>`;
}

const redirectPage = `<!DOCTYPE html>
<html lang="mul">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="Viking Bio integration for monitoring and managing pellet burner telemetry with a Pico-based bridge and local configurator." />
    <link rel="canonical" href="./en/" />
    <title>Viking Bio Integration</title>
  </head>
  <body>
    <noscript>
      <p><a href="./en/">English</a> | <a href="./sv/">Svenska</a> | <a href="./no/">Norsk</a> | <a href="./fi/">Suomi</a> | <a href="./da/">Dansk</a> | <a href="./is/">Íslenska</a></p>
    </noscript>
    <script>
      (function () {
        var locales = {
          en: 'en', 'en-us': 'en', 'en-gb': 'en',
          sv: 'sv', 'sv-se': 'sv',
          no: 'no', nb: 'no', nn: 'no',
          fi: 'fi',
          da: 'da',
          is: 'is'
        };
        var language = (navigator.language || navigator.userLanguage || 'en').toLowerCase();
        var preferred = locales[language] || 'en';
        if (language.indexOf('sv') === 0) preferred = 'sv';
        if (language.indexOf('no') === 0 || language.indexOf('nb') === 0 || language.indexOf('nn') === 0) preferred = 'no';
        if (language.indexOf('fi') === 0) preferred = 'fi';
        if (language.indexOf('da') === 0) preferred = 'da';
        if (language.indexOf('is') === 0) preferred = 'is';
        window.location.replace('./' + preferred + '/');
      })();
    <\/script>
  </body>
</html>`;

for (const locale of Object.keys(pages)) {
  const targetDir = path.join(root, locale);
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, 'index.html'), renderPage(pages[locale]), 'utf8');
}
fs.writeFileSync(path.join(root, 'index.html'), redirectPage, 'utf8');

console.log('Generated docs landing pages for: ' + Object.keys(pages).join(', '));
