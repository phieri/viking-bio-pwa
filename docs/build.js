/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

// Static docs generator for the multilingual landing pages.
// The generated HTML files in docs/<lang>/ and docs/index.html are committed build artifacts.
// Regenerate from the repo root with: node docs/build.js

const fs = require('fs');
const path = require('path');

const root = __dirname;
const supportedLanguages = [
  { code: 'en', label: 'English', browserCodes: ['en'] },
  { code: 'sv', label: 'Svenska', browserCodes: ['sv'] },
  { code: 'no', label: 'Norsk', browserCodes: ['no', 'nb', 'nn'] },
  { code: 'fi', label: 'Suomi', browserCodes: ['fi'] },
  { code: 'da', label: 'Dansk', browserCodes: ['da'] },
  { code: 'is', label: 'Íslenska', browserCodes: ['is'] }
];

const languageDirectories = Object.fromEntries(
  supportedLanguages.map(({ code }) => [code, path.join(root, code)])
);

const pageCatalog = {
  en: {
    lang: 'en',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio integration for monitoring and managing pellet burner telemetry with a Pico-based bridge and local configurator.',
    brandAria: 'Viking Bio home',
    navAria: 'Main navigation',
    langAria: 'Language switcher',
    showcaseAria: 'Configurator and hardware overview',
    showcaseConfiguratorLabel: 'Browser notifications',
    showcaseNotificationLabel: 'Browser notifications',
    showcaseNotificationCaption:
      'This phone-style demo shows the separate browser app used to receive burner alerts, reminders, and delivery tests over notifications.',
    showcasePicoLabel: 'Pico placeholder',
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
    panelConfigurator: 'Go runtime with desktop app + terminal setup',
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
    featureNetworkTitle: 'Browser notifications',
    featureNetworkBody:
      'The runtime is built around a local-first model: the Go service exposes APIs and USB setup, while the separate push-pwa app handles browser notifications for burner alerts and reminders.',
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
      'The system separates the hardware-facing bridge from the Go runtime and the separate browser-push app. The Go runtime includes both a desktop app and a terminal-based setup flow for local provisioning and status checks, while the Pico reads burner data and streams signed telemetry to a Go process on the same trusted local network. That Go process exposes the API and USB configuration flow while the bridge stays focused on measurement, ingest, and alert delivery.',
    stack1: 'Burner serial data',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signed TCP ingest',
    stack4: 'Go runtime with desktop app + terminal setup + local APIs',
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
    brandAria: 'Viking Bio startsida',
    navAria: 'Huvudnavigering',
    langAria: 'Språkval',
    showcaseAria: 'Konfigurator och hårdvaruöversikt',
    showcaseConfiguratorLabel: 'Konfiguratorplatshållare',
    showcasePicoLabel: 'Pico-platshållare',
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
    panelConfigurator: 'Go runtime with desktop app + terminal setup',
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
    featureNetworkTitle: 'Local runtime with desktop app + terminal setup',
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
      'Systemet separerar hårdvarunära bryggan från den Go-runtimen och den separata browser-push-appen. Pico läser brännardata och strömmar signerad telemetri till en Go-process i samma lokala nätverk. Den processen exponeras via API och USB-konfigurationsflöde medan bryggan fokuserar på mätning, ingest och varningstillförsel.',
    stack1: 'Seriedata från brännaren',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signerad TCP-ingest',
    stack4: 'Go runtime with desktop app + terminal setup + local APIs',
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
      'Viking Bio-integrasjon for å overvåke og administrere pelletbrenseltelemetri med en Pico-basert bro og lokal konfigurasjon.',
    brandAria: 'Viking Bio startside',
    navAria: 'Hovednavigasjon',
    langAria: 'Språkvalg',
    showcaseAria: 'Konfigurasjon og maskinvareoversikt',
    showcaseConfiguratorLabel: 'Konfigurasjon platsholder',
    showcasePicoLabel: 'Pico platsholder',
    nav: ['Oversikt', 'Funksjoner', 'Arkitektur', 'Prosjekt'],
    heroEyebrow: 'Overvåkning av pelletfyr',
    heroTitle: 'Gjør en Viking Bio 20 til et koblet, observerbart varmesystem',
    heroLead:
      'Dette prosjektet kombinerer en Raspberry Pi Pico-bro, signert telemetri og en lokal Go-konfigurator for å overvåke brennerens helse, spore driftstilstand og forenkle oppsett på hjemmenettverk eller eiendom.',
    showcaseTitle: 'Lokal installasjon fra skrivebordet',
    showcaseConfiguratorAlt:
      'Viking Bio konfigurasjonsskjerm som viser enhetsstatus, Wi‑Fi-konfigurasjon og lokale oppsettshandlinger.',
    showcaseConfiguratorCaption:
      'Det lokale konfigurasjonsskjermet samler oppstart, provisionering og statuskontroll i ett skrivebordsflyt.',
    showcasePicoAlt: 'Illustrasjon av Raspberry Pi Pico 2 W for den lokale brennerbroen.',
    showcasePicoCaption:
      'Pico 2 W fungerer som den lille, lavenergibroen mellom brenneren og den lokale runtime-en.',
    ctaExplore: 'Utforsk prosjektet',
    ctaSource: 'Vis kildekode',
    sourceAria: 'Vis kildekode på GitHub (åpnes i ny fane)',
    footerGitHubAria: 'Viking Bio-prosjekt på GitHub (åpnes i ny fane)',
    panelLabel: 'Telemetriflyt',
    panelConfigurator: 'Go runtime with desktop app + terminal setup',
    panelItem1: 'UART-lesing fra brennerutdata',
    panelItem2: 'Signert TCP-strøm til lokal runtime',
    panelItem3: 'Lokal API + USB-oppsettsflyt',
    overviewEyebrow: 'Oversikt',
    overviewTitle: 'Bygget for pålitelighet, synlighet og lokalt eierskap',
    cardBridgeTitle: 'Pålitelig bro',
    cardBridgeBody:
      'En Pico W / Pico 2 W-firmware leser brennerens UART-strøm, lagrer Wi‑Fi- og tjenerinnstillinger lokalt og videreformidler signert telemetri over en stabil TCP-tilkobling.',
    cardControlTitle: 'Lokal kontrollplane',
    cardControlBody:
      'Go-konfiguratoren håndterer onboarding, brostatus og lokal runtime uten å bli avhengig av ekstern nettjeneste eller hostet webapp.',
    cardInsightTitle: 'Driftsinnsikt',
    cardInsightBody:
      'Prosjektet er designet for å vise brennerstatus og feilsituasjoner gjennom et lokalt API og en separat browser-push-app, uten å tilby et dashboard i roten.',
    featuresEyebrow: 'Funksjoner',
    featuresTitle: 'Alt du trenger for å gjøre en brenner smartere uten å miste kontrollen',
    featureTelemetryTitle: 'Signert telemetri',
    featureTelemetryBody:
      'Hver melding er autentisert med en enhetsnøkkel, slik at den lokale tjeneren kan verifisere innkommende brennerdata.',
    featureUSBTitle: 'USB-oppsett',
    featureUSBBody:
      'Bro-oppsett kan skje via seriel port med grafisk eller terminalbasert konfigurasjon, som gjør installasjonen enkel.',
    featureNetworkTitle: 'Local runtime with desktop app + terminal setup',
    featureNetworkBody:
      'Runtimeen er bygget rundt en lokal, enhetsorientert modell: Go-tjenesten eksponerer API-er og USB-oppsett, mens nettvarsel håndteres av den separate push-pwa-appen.',
    featureMDNSTitle: 'mDNS-oppdagelse',
    featureMDNSBody:
      'Broen lyttes etter mDNS-varsler fra konfiguratoren, som gjør automatisk tjenesteoppdagelse på hjemmenettverk mulig uten manuell konfigurasjon.',
    featureStateTitle: 'Varig tilstand',
    featureStateBody:
      'Wi‑Fi-opplysninger, tjenerinnstillinger og enhetsidentitet lagres i lokal flashbasert lagring.',
    featureHardwareTitle: 'Åpen maskinva',
    featureHardwareBody:
      'Repoet er bevisst gjennomskuelig: firmware, protokolllogikk, runtime og konfigurasjonsverktøy ligger samlet.',
    architectureEyebrow: 'Arkitektur',
    architectureTitle: 'Enkelt lagdelt flyt, tydelig ansvar og lokal-first design',
    architectureBody:
      'Systemet skiller broen som er nær hardwaren fra den Go-runtimeen og den separate browser-push-appen. Picoen leser brennerdata og sender signert telemetri til en Go-prosess på samme lokale nettverk. Den prosessen eksponerer API og USB-konfigurasjonsflyt, mens broen holder fokus på måling, ingest og varsling.',
    stack1: 'Seriedata fra brenneren',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signert TCP-ingest',
    stack4: 'Go runtime with desktop app + terminal setup + local APIs',
    stack5: 'push-pwa nettvarsler',
    projectEyebrow: 'Prosjekt',
    projectTitle: 'Bygget for eiere, integratorer og skapere som vil ha en praktisk brennermonitor',
    projectBody1:
      'Dette repoet er et komplett integrasjonsprosjekt for Viking Bio 20 pelletbrenneren: firmware, protokollanalyse, lokal runtime og en egen browser-push-app for operatørvarsler. Det er designet for å være forståelig, utvidbart og enkelt å kjøre på liten lokal maskinvare eller hjemmenettverk.',
    projectBody2:
      'Fokuset er på ærlig operasjonell kontroll: hold data lokalt, verifiser enheten i kanten og gi et pålitelig konfigurasjonsflyt uten å være avhengig av et hostet produkt eller cloud-backend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  fi: {
    lang: 'fi',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio -integraatio pelletikattilan telemetrian seuraamiseen ja hallintaan Pico-pohjaisen silta- ja paikallisen konfiguraattorin avulla.',
    brandAria: 'Viking Bio etusivu',
    navAria: 'Päävalikko',
    langAria: 'Kielivalikko',
    showcaseAria: 'Konfiguraattori ja laitteisto',
    showcaseConfiguratorLabel: 'Konfiguraattori-paikanpitäjä',
    showcasePicoLabel: 'Pico-paikanpitäjä',
    nav: ['Yleiskatsaus', 'Ominaisuudet', 'Arkkitehtuuri', 'Projekti'],
    heroEyebrow: 'Pellettikattilan valvonta',
    heroTitle: 'Tee Viking Bio 20:stä yhdistetty ja nähtävä lämmitysjärjestelmä',
    heroLead:
      'Tämä projekti yhdistää Raspberry Pi Pico -sillan, allekirjoitetun telemetrian ja paikallisen Go-konfiguraattorin, jotta kattilan terveyttä voidaan seurata, käyttötilaa analysoida ja asennus helpottuu kodin tai kiinteistön verkossa.',
    showcaseTitle: 'Paikallinen asennus työpöydältä',
    showcaseConfiguratorAlt:
      'Viking Bio -konfiguraattorin käyttöliittymä, jossa näkyvät laitteen tila, Wi‑Fi-asetukset ja paikalliset toiminnot.',
    showcaseConfiguratorCaption:
      'Paikallinen konfiguraattori pitää verkon asennuksen, provisionoinnin ja tilan tarkastelun yhdessä työpöytävirrassa.',
    showcasePicoAlt: 'Raspberry Pi Pico 2 W -piirin kuva paikalliselle kattilasiltaosalle.',
    showcasePicoCaption:
      'Pico 2 W toimii pienenä, energiatehokkaana sillana kattilan ja paikallisen ajonaikaisen ympäristön välillä.',
    ctaExplore: 'Tutustu projektiin',
    ctaSource: 'Näytä lähdekoodi',
    sourceAria: 'Näytä lähdekoodi GitHubissa (avautuu uuteen välilehteen)',
    footerGitHubAria: 'Viking Bio -projekti GitHubissa (avautuu uuteen välilehteen)',
    panelLabel: 'Telemetriavirta',
    panelConfigurator: 'Go runtime with desktop app + terminal setup',
    panelItem1: 'UART-lukeminen kattilasta',
    panelItem2: 'Allekirjoitettu TCP-virta paikalliseen ajonaikaiseen ympäristöön',
    panelItem3: 'Paikallinen API + USB-provisionointivirta',
    overviewEyebrow: 'Yleiskatsaus',
    overviewTitle: 'Rakennettu luotettavuuteen, näkyvyyteen ja paikalliseen omistajuuteen',
    cardBridgeTitle: 'Luotettava silta',
    cardBridgeBody:
      'Pico W / Pico 2 W -ohjelmisto lukee kattilan UART-virran, tallentaa Wi‑Fi- ja palvelinasetukset paikallisesti ja välittää allekirjoitettua telemetriaa vakaalla TCP-yhteydellä.',
    cardControlTitle: 'Paikallinen ohjaustaso',
    cardControlBody:
      'Go-konfiguraattori hallitsee käyttöönottoa, sillan tilaa ja paikallista ajonaikaista ympäristöä ilman riippuvuutta etäpalvelusta tai isännöidystä web-sovelluksesta.',
    cardInsightTitle: 'Toimintatiedot',
    cardInsightBody:
      'Projekti on suunniteltu näyttämään kattilan tila ja virheet paikallisen API:n ja erillisen selainpush-sovelluksen kautta ilman, että juuria palvelta tuodaan dashboardia.',
    featuresEyebrow: 'Ominaisuudet',
    featuresTitle: 'Kaikki mitä tarvitaan, jotta kattila tulee älykkäämmäksi ilman hallinnan menettämistä',
    featureTelemetryTitle: 'Allekirjoitettu telemetria',
    featureTelemetryBody:
      'Jokainen viesti on autentikoitu laiteavaimella, joten paikallinen palvelin voi tarkistaa tulevat kattilatiedot.',
    featureUSBTitle: 'USB-provisionointi',
    featureUSBBody:
      'Sillan asennus voidaan tehdä sarjaportin kautta GUI- tai terminaalipohjaisella konfiguraattorilla, mikä tekee asennuksesta helppoa.',
    featureNetworkTitle: 'Local runtime with desktop app + terminal setup',
    featureNetworkBody:
      'Ajonaikainen järjestelmä on rakennettu paikalliseen, laitekeskeiseen malliin: Go-palvelu tarjoaa API:t ja USB-asetukset, kun taas selainilmoitukset käsitellään erillisessä push-pwa-sovelluksessa.',
    featureMDNSTitle: 'mDNS-haku',
    featureMDNSBody:
      'Silta kuuntelee mDNS-ilmoituksia konfiguraattorilta, mikä mahdollistaa automaattisen palveluiden löytämisen kotiverkossa ilman manuaalista konfiguraatiota.',
    featureStateTitle: 'Pysyvä tila',
    featureStateBody:
      'Wi‑Fi-kirjaukset, palvelinasetukset ja laiteiden identiteetit säilytetään paikallisessa flash-pohjaisessa tallennustilassa.',
    featureHardwareTitle: 'Avoin laitepolku',
    featureHardwareBody:
      'Tietovarasto on tarkoituksella läpinäkyvä: laiteohjelmisto, protokollilogiikka, ajonaikainen ympäristö ja konfigurointityökalut ovat yhdessä.',
    architectureEyebrow: 'Arkkitehtuuri',
    architectureTitle: 'Yksinkertainen kerroksellinen virta, selkeä vastuunjako ja paikallisesti toimiva malli',
    architectureBody:
      'Järjestelmä erottaa laitteeseen liittyvän sillan Go-ajonaikaisesta ympäristöstä ja erillisestä selainpush-sovelluksesta. Pico lukee kattilatiedot ja lähettää allekirjoitettua telemetriaa samaan luotettuun paikalliseen verkkoon. Tämä Go-prosessi tarjoaa API:t ja USB-asennusvirran, kun taas silta keskittyy mittaukseen, tiedon vastaanottoon ja hälytyksiin.',
    stack1: 'Kattilan sarjadata',
    stack2: 'Pico W / Pico 2 W -laiteohjelmisto',
    stack3: 'Allekirjoitettu TCP-ingest',
    stack4: 'Go runtime with desktop app + terminal setup + local APIs',
    stack5: 'push-pwa-selainilmoitukset',
    projectEyebrow: 'Projekti',
    projectTitle: 'Rakennettu omistajille, integraattoreille ja tekijöille, jotka haluavat käytännöllisen kattilavalvonnan',
    projectBody1:
      'Tämä tietovarasto on täydellinen integraatioprojekti Viking Bio 20 -pelletikattilalle: laiteohjelmisto, protokollan jäsentäminen, paikallinen ajonaikainen ympäristö ja erillinen selainpush-sovellus operaattorihälytyksiin. Se on suunniteltu ymmärrettäväksi, laajennettavaksi ja helposti ajettavaksi pienellä paikallisella laitteella tai kotiverkossa.',
    projectBody2:
      'Keskiössä on rehellinen operatiivinen hallinta: pidä data paikallisesti, varmista laite reunassa ja tarjoa luotettava konfigurointivirtuaali ilman riippuvuutta isännöidyssä tuotteessa tai pilvipalvelussa.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  da: {
    lang: 'da',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio-integration til overvågning og styring af pelletbrændertelemetri med en Pico-baseret bro og lokal konfigurator.',
    brandAria: 'Viking Bio startside',
    navAria: 'Hovednavigation',
    langAria: 'Sprogskifter',
    showcaseAria: 'Konfigurator og hardwareoversigt',
    showcaseConfiguratorLabel: 'Konfigurator pladsholder',
    showcasePicoLabel: 'Pico pladsholder',
    nav: ['Oversigt', 'Funktioner', 'Arkitektur', 'Projekt'],
    heroEyebrow: 'Overvågning af pelletsbrænder',
    heroTitle: 'Gør en Viking Bio 20 til et forbundet, observerbart varmesystem',
    heroLead:
      'Dette projekt kombinerer en Raspberry Pi Pico-bro, signeret telemetri og en lokal Go-konfigurator for at overvåge brænderens tilstand, spore driftsstatus og forenkle opsætning på hjemmet eller ejendommen.',
    showcaseTitle: 'Lokal opsætning fra skrivebordet',
    showcaseConfiguratorAlt:
      'Viking Bio-konfigurationsvisning, der viser enhedens status, Wi‑Fi-konfiguration og lokale opsætningshandlinger.',
    showcaseConfiguratorCaption:
      'Det lokale konfigurationsflow samler opstart, provisionering og statuskontrol i et enkelt skrivebordsflow.',
    showcasePicoAlt: 'Illustration af Raspberry Pi Pico 2 W til den lokale brænderbro.',
    showcasePicoCaption:
      'Pico 2 W fungerer som den lille, energieffektive bro mellem brænderen og den lokale runtime.',
    ctaExplore: 'Udforsk projektet',
    ctaSource: 'Vis kildekode',
    sourceAria: 'Vis kildekode på GitHub (åbner i ny fane)',
    footerGitHubAria: 'Viking Bio-projekt på GitHub (åbner i ny fane)',
    panelLabel: 'Telemetriflow',
    panelConfigurator: 'Go runtime with desktop app + terminal setup',
    panelItem1: 'UART-læsning fra brænderens output',
    panelItem2: 'Signeret TCP-stream til lokal runtime',
    panelItem3: 'Lokalt API + USB-provisioneringsflow',
    overviewEyebrow: 'Oversigt',
    overviewTitle: 'Bygget til pålidelighed, synlighed og lokalt ejerskab',
    cardBridgeTitle: 'Pålidelig bro',
    cardBridgeBody:
      'En Pico W / Pico 2 W-firmware læser brænderens UART-strøm, gemmer Wi‑Fi- og serverindstillinger lokalt og videresender signeret telemetri via en stabil TCP-forbindelse.',
    cardControlTitle: 'Lokal kontrolplan',
    cardControlBody:
      'Go-konfiguratoren håndterer onboarding, brostatus og lokal runtime uden at skabe afhængighed af en ekstern tjeneste eller hostet webapp.',
    cardInsightTitle: 'Driftsindsigt',
    cardInsightBody:
      'Projektet er designet til at vise brænderstatus og fejl via et lokalt API og en separat browser-push-app uden at serve et dashboard i roden.',
    featuresEyebrow: 'Funktioner',
    featuresTitle: 'Alt, hvad der skal til for at gøre en brænder smartere uden at miste kontrollen',
    featureTelemetryTitle: 'Signeret telemetri',
    featureTelemetryBody:
      'Hver meddelelse er autentificeret med en enhedsnykkel, så den lokale server kan verificere indkommende brænderdata.',
    featureUSBTitle: 'USB-provisionering',
    featureUSBBody:
      'Broopsætning kan ske via seriel port med GUI eller terminalbaseret konfigurator, hvilket gør installationen enkel.',
    featureNetworkTitle: 'Local runtime with desktop app + terminal setup',
    featureNetworkBody:
      'Runtimeen er bygget omkring en lokal, enhedsorienteret model: Go-tjenesten eksponerer API’er og USB-oprettelse, mens browsernotifikationer håndteres af den separate push-pwa-app.',
    featureMDNSTitle: 'mDNS-opdagelse',
    featureMDNSBody:
      'Broen lytter efter mDNS-meddelelser fra konfiguratoren, hvilket muliggør automatisk tjenesteopdagelse på hjemmenetværk uden manuel konfiguration.',
    featureStateTitle: 'Bestående tilstand',
    featureStateBody:
      'Wi‑Fi-legitimationsoplysninger, serverindstillinger og enhedsidentitet lagres lokalt i flash-baseret lager.',
    featureHardwareTitle: 'Åben hardwarevej',
    featureHardwareBody:
      'Repoet er bevidst gennemsigtigt: firmware, protokolparsering, runtime og konfigurationsværktøjer ligger sammen.',
    architectureEyebrow: 'Arkitektur',
    architectureTitle: 'Simpelt lagdelt flow, tydeligt ansvar og lokal-first design',
    architectureBody:
      'Systemet adskiller hardware-nære broen fra den Go-runtime og den separate browser-push-app. Picoen læser brænderdata og strømmer signeret telemetri til en Go-proces på samme lokale netværk. Den proces eksponerer API og USB-konfigurationsflow, mens broen holder fokus på måling, ingest og advarselslevering.',
    stack1: 'Seriedata fra brænderen',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signeret TCP-ingest',
    stack4: 'Go runtime with desktop app + terminal setup + local APIs',
    stack5: 'push-pwa browsernotifikationer',
    projectEyebrow: 'Projekt',
    projectTitle: 'Bygget til ejere, integratorer og gør-det-selv-entusiaster, der vil have en praktisk brændermonitor',
    projectBody1:
      'Dette repo er et komplet integrationsprojekt til Viking Bio 20 pelletbrænderen: firmware, protokolanalyse, lokal runtime og en separat browser-push-app til operatøralarmer. Det er designet til at være forståeligt, udvideligt og nemt at køre på lille lokal hardware eller hjemmenetværk.',
    projectBody2:
      'Fokus er ærlig driftskontrol: hold data lokalt, verificér enheden i kanten og lever et pålideligt konfigurationsflow uden at være afhængig af et hostet produkt eller cloud-backend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  },
  is: {
    lang: 'is',
    title: 'Viking Bio Integration',
    metaDescription:
      'Viking Bio-samþætting til eftirlits og stjórnun á pelletsofntelemetríu með Pico-byggðri brú og staðbundnum stillingarhjálp.',
    brandAria: 'Viking Bio heimasíða',
    navAria: 'Aðalvalmynd',
    langAria: 'Tungumálaval',
    showcaseAria: 'Stillingarhjálp og tæknivönding',
    showcaseConfiguratorLabel: 'Stillingarhjálp staðgengill',
    showcasePicoLabel: 'Pico staðgengill',
    nav: ['Yfirlit', 'Eiginleikar', 'Bygging', 'Verkefni'],
    heroEyebrow: 'Eftirlit með pelletsofni',
    heroTitle: 'Gerðu Viking Bio 20 að tengdu, sérhannaðri hitakerfi',
    heroLead:
      'Þetta verkefni sameinar Raspberry Pi Pico-brú, undirritaða telemetríu og staðbundna Go-stillingarhjálp til að fylgjast með heilsu ofnsins, rekja aðgerðarástand og einfalda uppsetningu á heimavelli eða fasteign.',
    showcaseTitle: 'Staðbundin uppsetning frá skjáborðinu',
    showcaseConfiguratorAlt:
      'Viking Bio stillingarviðmót sem sýnir stöðu tækis, Wi‑Fi-stillingar og staðbundnar aðgerðir.',
    showcaseConfiguratorCaption:
      'Staðbundið stillingarviðmót heldur uppsetningu, þjónustuskipulag og ástandsathugun í einu skrifborðsflæði.',
    showcasePicoAlt: 'Teikning af Raspberry Pi Pico 2 W fyrir staðbundna ofnabrú.',
    showcasePicoCaption:
      'Pico 2 W virkar sem litla, orkusparandi brú milli ofnsins og staðbundins keyrsluumhverfis.',
    ctaExplore: 'Skoða verkefnið',
    ctaSource: 'Sjá kóða',
    sourceAria: 'Sjá kóða á GitHub (opnast í nýjum flipa)',
    footerGitHubAria: 'Viking Bio-verkefni á GitHub (opnast í nýjum flipa)',
    panelLabel: 'Telemetríuflæði',
    panelConfigurator: 'Go runtime with desktop app + terminal setup',
    panelItem1: 'UART-lesning frá ofninum',
    panelItem2: 'Undirritað TCP-flæði til staðbundins keyrsluumhverfis',
    panelItem3: 'Staðbundið API + USB-uppsetningarflæði',
    overviewEyebrow: 'Yfirlit',
    overviewTitle: 'Byggt fyrir áreiðanleika, sýnileika og staðbundið eignarhald',
    cardBridgeTitle: 'Áreiðanleg brú',
    cardBridgeBody:
      'Pico W / Pico 2 W firmware les úr UART-flæði ofnsins, geymir Wi‑Fi- og þjónustustillingar staðbundið og sendir undirritaða telemetríu yfir stöðuga TCP-tengingu.',
    cardControlTitle: 'Staðbundinn stjórnplani',
    cardControlBody:
      'Go-stillingarhjálpin sér um uppsetningu, brúarstöðu og staðbundið keyrsluumhverfi án þess að þurfa fjarlægan þjónustu eða hýst webforrit.',
    cardInsightTitle: 'Rekstrarupplýsingar',
    cardInsightBody:
      'Verkefnið er hannað til að sýna stöðu ofns og bilanir með staðbundnu API og sjálfstæðu vafra-push-forriti án þess að bjóða upp á dashboard í rótinni.',
    featuresEyebrow: 'Eiginleikar',
    featuresTitle: 'Allt sem þarf til að gera ofn skynsamari án þess að tapa stjórninni',
    featureTelemetryTitle: 'Undirrituð telemetría',
    featureTelemetryBody:
      'Hver skilaboð eru auðkennd með tæki-lyklinum svo staðbundinn þjónn geti staðfest innkomandi gögn frá ofninum.',
    featureUSBTitle: 'USB-uppsetning',
    featureUSBBody:
      'Brúaruppsetning getur farið fram yfir raðtengi með GUI eða skeljaprófunarstillingu, sem einfaldar uppsetningu.',
    featureNetworkTitle: 'Local runtime with desktop app + terminal setup',
    featureNetworkBody:
      'Keyrsluumhverfið er byggt á staðbundnu, tæki-fókusuðu líkani: Go-þjónustan leggur fyrir API og USB-uppsetningu, en vafra-tilkynningar eru meðhöndlaðar af sérstöku push-pwa-forriti.',
    featureMDNSTitle: 'mDNS-uppgötvun',
    featureMDNSBody:
      'Brúin hlustar eftir mDNS-tilkynningum frá stillingarhjálpinni, sem gerir sjálfvirka þjónustuleit á heimavefneti án handvirkrar stillingar.',
    featureStateTitle: 'Varanlegur ástand',
    featureStateBody:
      'Wi‑Fi-lykilorð, þjónustustillingar og auðkenni tækja eru geymd í staðbundnu flash-safni.',
    featureHardwareTitle: 'Opinn vélbúnaðargangur',
    featureHardwareBody:
      'Geymslan er viljandi gegnsæ: firmware, samskiptalogik, keyrsluumhverfi og stillingarverkfæri liggja saman.',
    architectureEyebrow: 'Bygging',
    architectureTitle: 'Einfalt lögskipt flæði, skýr ábyrgð og staðbundið hönnunarmót',
    architectureBody:
      'Kerfið aðskilur vélbúnaðarlega brúna frá Go-keyrsluumhverfinu og sjálfstæðu vafra-push-forriti. Pico les ofngögn og streymir undirrituðu telemetríu til Go-ferlis á sama staðbundna neti. Sú vinna kemur með API og USB-uppsetningarflæði en brúin heldur fókus á mælingar, innflutning og viðvaranir.',
    stack1: 'Raðgögn frá ofninum',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Undirritað TCP-ingest',
    stack4: 'Go runtime with desktop app + terminal setup + local APIs',
    stack5: 'push-pwa vafra-tilkynningar',
    projectEyebrow: 'Verkefni',
    projectTitle: 'Byggt fyrir eigendur, samþættingaraðila og hagnýta skapara sem vilja hagnýta ofnstjórnun',
    projectBody1:
      'Þetta geymslurými er fullkomið samþættingarverkefni fyrir Viking Bio 20 pelletsofninn: firmware, samskiptumgjöf, staðbundið keyrsluumhverfi og sértakt vafra-push-forrit fyrir rekstrarviðvaranir. Það er hannað til að vera skiljanlegt, framlengjanlegt og auðvelt að keyra á litlu staðbundnu tæki eða heimaneti.',
    projectBody2:
      'Fókusinn er heiðarleg rekstrarstjórnun: haltu gögnum á staðnum, staðfestu tækið í jaðrinum og bjóððu upp á áreiðanlegt stillingarflæði án þess að treysta á hýst vörur eða skýjabakenda.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  }
};

function buildPage(code) {
  return {
    ...pageCatalog.en,
    ...(pageCatalog[code] || {}),
    lang: code
  };
}

function languageHref(code, currentCode) {
  return code === currentCode ? './' : `../${code}/`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const pushPwaPublicDir = path.join(root, '..', 'push-pwa', 'public');
const pushPwaHtml = fs.readFileSync(path.join(pushPwaPublicDir, 'index.html'), 'utf8');
const pushPwaCss = fs.readFileSync(path.join(pushPwaPublicDir, 'style.css'), 'utf8');
const pushPwaAppJs = fs.readFileSync(path.join(pushPwaPublicDir, 'app.js'), 'utf8');

function buildPushPwaDemoDocument() {
  const demoScript = `
    (function () {
      function applyDemoValues() {
        const senderField = document.getElementById('subscription-sender');
        if (senderField) senderField.value = 'viking-bio-01';

        const priorityField = document.getElementById('subscription-priority');
        if (priorityField) priorityField.value = 'normal';

        const languageField = document.getElementById('app-language');
        if (languageField) languageField.value = 'en';

        const notificationLow = document.getElementById('notification-level-low');
        if (notificationLow) notificationLow.checked = true;
        const notificationNormal = document.getElementById('notification-level-normal');
        if (notificationNormal) notificationNormal.checked = true;
        const notificationHigh = document.getElementById('notification-level-high');
        if (notificationHigh) notificationHigh.checked = true;

        const yamlBox = document.getElementById('subscription-yaml');
        if (yamlBox) {
          yamlBox.value = 'sender: viking-bio-01\npriority: normal\nnotificationLevel:\n  low: true\n  normal: true\n  high: true\n';
        }

        const lastContact = document.getElementById('last-contact-status');
        if (lastContact) lastContact.textContent = 'Last device contact: 08:45';

        const rssi = document.getElementById('rssi-status');
        if (rssi) rssi.textContent = 'RSSI: -51 dBm';

        const lfs = document.getElementById('lfs-status');
        if (lfs) lfs.textContent = 'LittleFS: healthy';

        const status = document.getElementById('status');
        if (status) status.textContent = 'Demo data loaded';

        const installBanner = document.getElementById('install-banner');
        if (installBanner) installBanner.classList.add('hidden');
      }

      window.addEventListener('DOMContentLoaded', applyDemoValues);
      setTimeout(applyDemoValues, 0);
    })();
  `;

  return pushPwaHtml
    .replace(/<link rel="stylesheet" href="\/style.css">/i, '<style>' + pushPwaCss + '</style>')
    .replace(/<script src="\/app.js" defer><\/script>/i, '<script>' + pushPwaAppJs + demoScript + '</script>');
}

const notificationDemoIframe = buildPushPwaDemoDocument();

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
        <a class="brand" href="#top" aria-label="${escapeHtml(data.brandAria)}">
          <span class="brand-mark">V</span>
          <span>Viking Bio</span>
        </a>
        <nav class="nav-links" aria-label="${escapeHtml(data.navAria)}">
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
 
      <section class="section showcase" aria-label="${escapeHtml(data.showcaseAria)}">
        <div class="container showcase-grid">
          <figure class="media-card phone-card">
            <div class="device-frame">
              <iframe class="phone-screen" title="${escapeHtml(data.showcaseNotificationLabel)}" srcdoc="${escapeHtml(notificationDemoIframe)}"></iframe>
            </div>
            <figcaption>${escapeHtml(data.showcaseNotificationCaption)}</figcaption>
          </figure>
          <figure class="media-card placeholder">
            <span>${escapeHtml(data.showcasePicoLabel)}</span>
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
        <div class="footer-actions">
          <label class="footer-language-label" for="language-select">${escapeHtml(data.langAria)}</label>
          <select
            id="language-select"
            class="language-select"
            aria-label="${escapeHtml(data.langAria)}"
            onchange="if (this.value) window.location.href = this.value;"
          >
            ${supportedLanguages
              .map(({ code, label }) => {
                const selected = code === data.lang ? ' selected' : '';
                return `<option value="${languageHref(code, data.lang)}"${selected}>${escapeHtml(label)}</option>`;
              })
              .join('')}
          </select>
          <a href="https://github.com/phieri/viking-bio-pwa" target="_blank" rel="noopener noreferrer" aria-label="${escapeHtml(data.footerGitHubAria)}">${escapeHtml(data.footerGitHub)}</a>
        </div>
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
      <p>${supportedLanguages.map(({ code, label }) => `<a href="./${code}/">${label}</a>`).join(' | ')}</p>
    </noscript>
    <script>
      (function () {
        var supported = ${JSON.stringify(supportedLanguages)};
        var preferredList = Array.isArray(navigator.languages) && navigator.languages.length ? navigator.languages : [navigator.language || 'en'];
        function normalise(value) {
          return String(value || '').toLowerCase().replace('_', '-');
        }
        function pickLanguage() {
          for (var i = 0; i < preferredList.length; i += 1) {
            var candidate = normalise(preferredList[i]);
            for (var j = 0; j < supported.length; j += 1) {
              var aliases = supported[j].browserCodes || [];
              for (var k = 0; k < aliases.length; k += 1) {
                if (candidate.indexOf(aliases[k]) === 0) {
                  return supported[j].code;
                }
              }
            }
          }
          return 'en';
        }
        var preferred = pickLanguage();
        window.location.replace('./' + preferred + '/');
      })();
    <\/script>
  </body>
</html>`;

for (const { code } of supportedLanguages) {
  const outputDir = languageDirectories[code];
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, 'index.html'), renderPage(buildPage(code)), 'utf8');
}
fs.writeFileSync(path.join(root, 'index.html'), redirectPage, 'utf8');

console.log(
  `Generated ${supportedLanguages.map(({ code }) => `docs/${code}/index.html`).join(', ')} and docs/index.html`
);
