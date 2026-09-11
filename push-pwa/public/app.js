/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

const SUPPORTED_LANGUAGES = [
  { code: 'en', label: 'English', browserCodes: ['en'] },
  { code: 'sv', label: 'Svenska', browserCodes: ['sv'] },
  { code: 'no', label: 'Norsk', browserCodes: ['no', 'nb', 'nn'] },
  { code: 'fi', label: 'Suomi', browserCodes: ['fi'] },
  { code: 'da', label: 'Dansk', browserCodes: ['da'] },
  { code: 'is', label: 'Íslenska', browserCodes: ['is'] },
];

const DEFAULT_LANGUAGE = 'en';
const MESSAGES = {
  en: {
    pageTitle: 'Viking Bio Alerts',
    eyebrow: 'Viking Bio',
    heading: 'Burner alerts',
    installTitle: 'Install this app',
    installHelp: 'On iPhone or iPad, tap the Share button and choose “Add to Home Screen”.',
    installButton: 'Install app',
    languageLabel: 'Language',
    senderLabel: 'Sender ID',
    senderPlaceholder: 'viking-bio-01',
    notificationLevels: 'Notification levels',
    notificationLevelLow: 'cleaning reminder',
    notificationLevelNormal: 'flame',
    notificationLevelHigh: 'error',
    priorityLabel: 'Test alert priority',
    priorityLow: 'low',
    priorityNormal: 'normal',
    priorityHigh: 'high',
    sendTest: 'Send test alert',
    yamlHelp: 'Generate a single YAML snippet for a client subscription and paste it into the subscription file manually.',
    generateYaml: 'Generate client YAML',
    copyYaml: 'Copy YAML',
    yamlAria: 'Subscription YAML snippet',
    waitingHeartbeat: 'Waiting for device heartbeat.',
    waitingRssi: 'Waiting for RSSI data.',
    waitingLfs: 'Waiting for LittleFS health.',
    waitingSubscription: 'Waiting for subscription data.',
    offlineTitle: 'Viking Bio device offline',
    offlineBody: '{device} appears to be offline.',
    lastContact: 'Last device contact: {label}',
    rssiUnavailable: 'RSSI: unavailable',
    rssiValue: 'RSSI: {value} dBm',
    lfsUnavailable: 'LittleFS: unavailable',
    lfsHealthTrue: 'LittleFS: healthy',
    lfsHealthFalse: 'LittleFS: degraded',
    unknownTime: 'Unknown time',
    noHeartbeatYet: 'No device heartbeat received yet.',
    bridgeDevice: 'Bridge device',
    heartbeatUnavailable: 'Heartbeat status unavailable.',
    loadingConfig: 'Loading app configuration...',
    registerServiceWorker: 'Registering service worker...',
    requestPermission: 'Requesting notification permission...',
    generatedYaml: 'Client subscription generated. Paste it into subscriptions.yaml.',
    sentCount: 'Sent {count} message(s).',
    copiedYaml: 'Subscription YAML copied to clipboard.',
    generateBeforeCopy: 'Generate a client YAML snippet before copying it.',
    useSafariInstall: 'Use the Share button in Safari, then choose “Add to Home Screen”.',
    installPromptMissing: 'The browser has not surfaced an install prompt yet.',
    loadHeartbeatError: 'Could not load device heartbeat status.',
    loadConfigError: 'Could not load the app configuration.',
    serviceWorkerUnsupported: 'Service workers are not supported in this browser.',
    pushUnsupported: 'This browser does not support Web Push notifications.',
    vapidFetchError: 'Could not fetch the VAPID public key.',
    vapidMissing: 'The VAPID key is missing from the server response.',
    permissionBeforeTest: 'Grant notification permission before sending a test message.',
    permissionDenied: 'Notification permission was not granted.',
    notificationsBlocked: 'Notifications are blocked.',
    testNotificationError: 'The test notification could not be sent.',
    testNotificationTitle: 'Test notification',
    testNotificationBody: 'This is a Viking Bio test alert from the push PWA.',
  },
  sv: {
    pageTitle: 'Viking Bio-varningar', heading: 'Brännarvarningar', installTitle: 'Installera appen',
    installHelp: 'På iPhone eller iPad trycker du på Dela och väljer ”Lägg till på hemskärmen”.',
    installButton: 'Installera app', languageLabel: 'Språk', senderLabel: 'Sändar-ID', senderPlaceholder: 'viking-bio-01',
    notificationLevels: 'Notifieringsnivåer', notificationLevelLow: 'rengöringspåminnelse', notificationLevelNormal: 'flamma', notificationLevelHigh: 'fel',
    priorityLabel: 'Prioritet för testvarning', priorityLow: 'låg', priorityNormal: 'normal', priorityHigh: 'hög', sendTest: 'Skicka testvarning',
    yamlHelp: 'Generera ett YAML-utdrag för en klientprenumeration och klistra in det manuellt i prenumerationsfilen.', generateYaml: 'Generera klient-YAML', copyYaml: 'Kopiera YAML', yamlAria: 'YAML-utdrag för prenumeration',
    waitingHeartbeat: 'Väntar på enhetens heartbeat.', waitingRssi: 'Väntar på RSSI-data.', waitingLfs: 'Väntar på LittleFS-hälsa.', waitingSubscription: 'Väntar på prenumerationsdata.',
    offlineTitle: 'Viking Bio-enhet offline', offlineBody: '{device} verkar vara offline.', lastContact: 'Senaste enhetskontakt: {label}',
    rssiUnavailable: 'RSSI: otillgänglig', rssiValue: 'RSSI: {value} dBm', lfsUnavailable: 'LittleFS: otillgängligt', lfsHealthTrue: 'LittleFS: frisk', lfsHealthFalse: 'LittleFS: degraderat', unknownTime: 'Okänd tid',
    noHeartbeatYet: 'Ingen enhets-heartbeat har tagits emot ännu.', bridgeDevice: 'Bryggenhet', heartbeatUnavailable: 'Heartbeat-status är otillgänglig.',
    loadingConfig: 'Läser appkonfiguration...', registerServiceWorker: 'Registrerar service worker...', requestPermission: 'Begär notifieringsbehörighet...',
    generatedYaml: 'Klientprenumerationen har genererats. Klistra in den i subscriptions.yaml.', sentCount: 'Skickade {count} meddelande(n).', copiedYaml: 'Prenumerations-YAML kopierades till urklipp.', generateBeforeCopy: 'Generera ett klient-YAML-utdrag innan du kopierar det.',
    useSafariInstall: 'Använd Dela-knappen i Safari och välj sedan ”Lägg till på hemskärmen”.', installPromptMissing: 'Webbläsaren har inte visat någon installationsprompt ännu.',
    loadHeartbeatError: 'Det gick inte att läsa heartbeat-status.', loadConfigError: 'Det gick inte att läsa appkonfigurationen.', serviceWorkerUnsupported: 'Service workers stöds inte i den här webbläsaren.', pushUnsupported: 'Den här webbläsaren stöder inte Web Push-notiser.', vapidFetchError: 'Det gick inte att hämta den publika VAPID-nyckeln.', vapidMissing: 'VAPID-nyckeln saknas i serversvaret.',
    permissionBeforeTest: 'Ge notifieringsbehörighet innan du skickar ett testmeddelande.', permissionDenied: 'Notifieringsbehörighet beviljades inte.', notificationsBlocked: 'Notifieringar är blockerade.', testNotificationError: 'Det gick inte att skicka testnotifieringen.', testNotificationTitle: 'Testnotifiering', testNotificationBody: 'Detta är en Viking Bio-testvarning från push-PWA:n.',
  },
  no: {
    pageTitle: 'Viking Bio-varsler', heading: 'Brennervarsler', installTitle: 'Installer appen',
    installHelp: 'På iPhone eller iPad trykker du på Del og velger «Legg til på Hjem-skjermen».',
    installButton: 'Installer app', languageLabel: 'Språk', senderLabel: 'Sender-ID', senderPlaceholder: 'viking-bio-01',
    notificationLevels: 'Varslingsnivåer', notificationLevelLow: 'rengjøringspåminnelse', notificationLevelNormal: 'flamme', notificationLevelHigh: 'feil',
    priorityLabel: 'Prioritet for testvarsel', priorityLow: 'lav', priorityNormal: 'normal', priorityHigh: 'høy', sendTest: 'Send testvarsel',
    yamlHelp: 'Generer ett YAML-utdrag for et klientabonnement og lim det manuelt inn i abonnementsfilen.', generateYaml: 'Generer klient-YAML', copyYaml: 'Kopier YAML', yamlAria: 'YAML-utdrag for abonnement',
    waitingHeartbeat: 'Venter på enhetens heartbeat.', waitingRssi: 'Venter på RSSI-data.', waitingLfs: 'Venter på LittleFS-helse.', waitingSubscription: 'Venter på abonnementsdata.',
    offlineTitle: 'Viking Bio-enhet frakoblet', offlineBody: '{device} ser ut til å være frakoblet.', lastContact: 'Siste enhetskontakt: {label}',
    rssiUnavailable: 'RSSI: utilgjengelig', rssiValue: 'RSSI: {value} dBm', lfsUnavailable: 'LittleFS: utilgjengelig', lfsHealthTrue: 'LittleFS: frisk', lfsHealthFalse: 'LittleFS: degradert', unknownTime: 'Ukjent tid',
    noHeartbeatYet: 'Ingen enhets-heartbeat er mottatt ennå.', bridgeDevice: 'Broenhet', heartbeatUnavailable: 'Heartbeat-status er utilgjengelig.',
    loadingConfig: 'Laster appkonfigurasjon...', registerServiceWorker: 'Registrerer service worker...', requestPermission: 'Ber om varslingstillatelse...',
    generatedYaml: 'Klientabonnementet ble generert. Lim det inn i subscriptions.yaml.', sentCount: 'Sendte {count} melding(er).', copiedYaml: 'Abonnements-YAML ble kopiert til utklippstavlen.', generateBeforeCopy: 'Generer et klient-YAML-utdrag før du kopierer det.',
    useSafariInstall: 'Bruk Del-knappen i Safari og velg deretter «Legg til på Hjem-skjermen».', installPromptMissing: 'Nettleseren har ikke vist et installasjonsvarsel ennå.',
    loadHeartbeatError: 'Kunne ikke laste heartbeat-statusen.', loadConfigError: 'Kunne ikke laste appkonfigurasjonen.', serviceWorkerUnsupported: 'Service workers støttes ikke i denne nettleseren.', pushUnsupported: 'Denne nettleseren støtter ikke Web Push-varsler.', vapidFetchError: 'Kunne ikke hente den offentlige VAPID-nøkkelen.', vapidMissing: 'VAPID-nøkkelen mangler i serversvaret.',
    permissionBeforeTest: 'Gi varslingstillatelse før du sender en testmelding.', permissionDenied: 'Varslingstillatelse ble ikke gitt.', notificationsBlocked: 'Varsler er blokkert.', testNotificationError: 'Testvarslet kunne ikke sendes.', testNotificationTitle: 'Testvarsel', testNotificationBody: 'Dette er et Viking Bio-testvarsel fra push-PWA-en.',
  },
  fi: {
    pageTitle: 'Viking Bio -hälytykset', heading: 'Polttimen hälytykset', installTitle: 'Asenna sovellus',
    installHelp: 'Napauta iPhonessa tai iPadissa Jaa-painiketta ja valitse ”Lisää Koti-valikkoon”.',
    installButton: 'Asenna sovellus', languageLabel: 'Kieli', senderLabel: 'Lähettäjän tunnus', senderPlaceholder: 'viking-bio-01',
    notificationLevels: 'Ilmoitustasot', notificationLevelLow: 'puhdistusmuistutus', notificationLevelNormal: 'liekki', notificationLevelHigh: 'virhe',
    priorityLabel: 'Testihälytyksen prioriteetti', priorityLow: 'matala', priorityNormal: 'normaali', priorityHigh: 'korkea', sendTest: 'Lähetä testihälytys',
    yamlHelp: 'Luo yksi YAML-katkelma asiakastilausta varten ja liitä se käsin tilaustiedostoon.', generateYaml: 'Luo asiakas-YAML', copyYaml: 'Kopioi YAML', yamlAria: 'Tilauksen YAML-katkelma',
    waitingHeartbeat: 'Odotetaan laitteen heartbeatia.', waitingRssi: 'Odotetaan RSSI-tietoja.', waitingLfs: 'Odotetaan LittleFS:n tilaa.', waitingSubscription: 'Odotetaan tilaustietoja.',
    offlineTitle: 'Viking Bio -laite ei ole verkossa', offlineBody: '{device} näyttää olevan poissa verkosta.', lastContact: 'Viimeisin laiteyhteys: {label}',
    rssiUnavailable: 'RSSI: ei saatavilla', rssiValue: 'RSSI: {value} dBm', lfsUnavailable: 'LittleFS: ei saatavilla', lfsHealthTrue: 'LittleFS: kunnossa', lfsHealthFalse: 'LittleFS: heikentynyt', unknownTime: 'Tuntematon aika',
    noHeartbeatYet: 'Laitteen heartbeatia ei ole vielä vastaanotettu.', bridgeDevice: 'Siltalaite', heartbeatUnavailable: 'Heartbeat-tila ei ole saatavilla.',
    loadingConfig: 'Ladataan sovelluksen asetuksia...', registerServiceWorker: 'Rekisteröidään service worker...', requestPermission: 'Pyydetään ilmoituslupaa...',
    generatedYaml: 'Asiakastilaus luotiin. Liitä se tiedostoon subscriptions.yaml.', sentCount: 'Lähetettiin {count} viestiä.', copiedYaml: 'Tilauksen YAML kopioitiin leikepöydälle.', generateBeforeCopy: 'Luo asiakas-YAML-katkelma ennen kopiointia.',
    useSafariInstall: 'Käytä Safarin Jaa-painiketta ja valitse sitten ”Lisää Koti-valikkoon”.', installPromptMissing: 'Selain ei ole vielä näyttänyt asennuskehotetta.',
    loadHeartbeatError: 'Laitteen heartbeat-tilaa ei voitu ladata.', loadConfigError: 'Sovelluksen asetuksia ei voitu ladata.', serviceWorkerUnsupported: 'Service worker -toimintoa ei tueta tässä selaimessa.', pushUnsupported: 'Tämä selain ei tue Web Push -ilmoituksia.', vapidFetchError: 'Julkista VAPID-avainta ei voitu hakea.', vapidMissing: 'VAPID-avain puuttuu palvelimen vastauksesta.',
    permissionBeforeTest: 'Anna ilmoituslupa ennen testiviestin lähettämistä.', permissionDenied: 'Ilmoituslupaa ei myönnetty.', notificationsBlocked: 'Ilmoitukset on estetty.', testNotificationError: 'Testi-ilmoitusta ei voitu lähettää.', testNotificationTitle: 'Testi-ilmoitus', testNotificationBody: 'Tämä on Viking Bion testihälytys push-PWA:sta.',
  },
  da: {
    pageTitle: 'Viking Bio-advarsler', heading: 'Brænderadvarsler', installTitle: 'Installér appen',
    installHelp: 'På iPhone eller iPad skal du trykke på Del og vælge ”Føj til hjemmeskærm”.',
    installButton: 'Installér app', languageLabel: 'Sprog', senderLabel: 'Afsender-ID', senderPlaceholder: 'viking-bio-01',
    notificationLevels: 'Notifikationsniveauer', notificationLevelLow: 'rengøringspåmindelse', notificationLevelNormal: 'flamme', notificationLevelHigh: 'fejl',
    priorityLabel: 'Prioritet for testadvarsel', priorityLow: 'lav', priorityNormal: 'normal', priorityHigh: 'høj', sendTest: 'Send testadvarsel',
    yamlHelp: 'Generér ét YAML-uddrag til et klientabonnement og indsæt det manuelt i abonnementsfilen.', generateYaml: 'Generér klient-YAML', copyYaml: 'Kopiér YAML', yamlAria: 'YAML-uddrag for abonnement',
    waitingHeartbeat: 'Venter på enhedens heartbeat.', waitingRssi: 'Venter på RSSI-data.', waitingLfs: 'Venter på LittleFS-sundhed.', waitingSubscription: 'Venter på abonnementsdata.',
    offlineTitle: 'Viking Bio-enhed offline', offlineBody: '{device} ser ud til at være offline.', lastContact: 'Seneste enhedskontakt: {label}',
    rssiUnavailable: 'RSSI: utilgængelig', rssiValue: 'RSSI: {value} dBm', lfsUnavailable: 'LittleFS: utilgængelig', lfsHealthTrue: 'LittleFS: sund', lfsHealthFalse: 'LittleFS: forringet', unknownTime: 'Ukendt tidspunkt',
    noHeartbeatYet: 'Der er endnu ikke modtaget heartbeat fra enheden.', bridgeDevice: 'Broenhed', heartbeatUnavailable: 'Heartbeat-status er utilgængelig.',
    loadingConfig: 'Indlæser appkonfiguration...', registerServiceWorker: 'Registrerer service worker...', requestPermission: 'Anmoder om notifikationstilladelse...',
    generatedYaml: 'Klientabonnementet blev genereret. Indsæt det i subscriptions.yaml.', sentCount: 'Sendte {count} besked(er).', copiedYaml: 'Abonnements-YAML blev kopieret til udklipsholderen.', generateBeforeCopy: 'Generér et klient-YAML-uddrag før kopiering.',
    useSafariInstall: 'Brug Del-knappen i Safari, og vælg derefter ”Føj til hjemmeskærm”.', installPromptMissing: 'Browseren har endnu ikke vist en installationsprompt.',
    loadHeartbeatError: 'Kunne ikke indlæse heartbeat-status.', loadConfigError: 'Kunne ikke indlæse appkonfigurationen.', serviceWorkerUnsupported: 'Service workers understøttes ikke i denne browser.', pushUnsupported: 'Denne browser understøtter ikke Web Push-notifikationer.', vapidFetchError: 'Kunne ikke hente den offentlige VAPID-nøgle.', vapidMissing: 'VAPID-nøglen mangler i serversvaret.',
    permissionBeforeTest: 'Giv notifikationstilladelse før du sender en testbesked.', permissionDenied: 'Notifikationstilladelse blev ikke givet.', notificationsBlocked: 'Notifikationer er blokeret.', testNotificationError: 'Testnotifikationen kunne ikke sendes.', testNotificationTitle: 'Testnotifikation', testNotificationBody: 'Dette er en Viking Bio-testadvarsel fra push-PWAen.',
  },
  is: {
    pageTitle: 'Viking Bio-tilkynningar', heading: 'Viðvaranir frá brennara', installTitle: 'Setja upp appið',
    installHelp: 'Á iPhone eða iPad skaltu ýta á Deila og velja „Bæta við heimaskjá“.',
    installButton: 'Setja upp app', languageLabel: 'Tungumál', senderLabel: 'Auðkenni sendanda', senderPlaceholder: 'viking-bio-01',
    notificationLevels: 'Tilkynningarstig', notificationLevelLow: 'hreinsunaráminning', notificationLevelNormal: 'logi', notificationLevelHigh: 'villa',
    priorityLabel: 'Forgangur prófunarviðvörunar', priorityLow: 'lágt', priorityNormal: 'venjulegt', priorityHigh: 'hátt', sendTest: 'Senda prófunarviðvörun',
    yamlHelp: 'Búðu til eitt YAML-brot fyrir áskrift viðskiptavinar og límdu það handvirkt inn í áskriftarskrána.', generateYaml: 'Búa til YAML fyrir viðskiptavin', copyYaml: 'Afrita YAML', yamlAria: 'YAML-brot fyrir áskrift',
    waitingHeartbeat: 'Bíð eftir heartbeat frá tæki.', waitingRssi: 'Bíð eftir RSSI-gögnum.', waitingLfs: 'Bíð eftir LittleFS-heilsu.', waitingSubscription: 'Bíð eftir áskriftargögnum.',
    offlineTitle: 'Viking Bio-tæki ótengt', offlineBody: '{device} virðist vera ótengt.', lastContact: 'Síðasta samband við tæki: {label}',
    rssiUnavailable: 'RSSI: ekki tiltækt', rssiValue: 'RSSI: {value} dBm', lfsUnavailable: 'LittleFS: ekki tiltækt', lfsHealthTrue: 'LittleFS: í lagi', lfsHealthFalse: 'LittleFS: skert', unknownTime: 'Óþekktur tími',
    noHeartbeatYet: 'Heartbeat frá tæki hefur ekki borist enn.', bridgeDevice: 'Brúartæki', heartbeatUnavailable: 'Heartbeat-staða er ekki tiltæk.',
    loadingConfig: 'Sæki stillingar appsins...', registerServiceWorker: 'Skrái service worker...', requestPermission: 'Bið um leyfi fyrir tilkynningum...',
    generatedYaml: 'Áskrift viðskiptavinar var búin til. Límdu hana inn í subscriptions.yaml.', sentCount: 'Sendi {count} skilaboð.', copiedYaml: 'Áskriftar-YAML var afritað á klippispjald.', generateBeforeCopy: 'Búðu til YAML-brot fyrir viðskiptavin áður en þú afritar.',
    useSafariInstall: 'Notaðu Deila-hnappinn í Safari og veldu síðan „Bæta við heimaskjá“.', installPromptMissing: 'Vafrinn hefur ekki birt uppsetningarboðið ennþá.',
    loadHeartbeatError: 'Ekki tókst að sækja heartbeat-stöðu.', loadConfigError: 'Ekki tókst að sækja stillingar appsins.', serviceWorkerUnsupported: 'Service workers eru ekki studdir í þessum vafra.', pushUnsupported: 'Þessi vafri styður ekki Web Push-tilkynningar.', vapidFetchError: 'Ekki tókst að sækja opinbera VAPID-lykilinn.', vapidMissing: 'VAPID-lykillinn vantar í svar þjónsins.',
    permissionBeforeTest: 'Veittu leyfi fyrir tilkynningum áður en þú sendir prufuskilaboð.', permissionDenied: 'Leyfi fyrir tilkynningum var ekki veitt.', notificationsBlocked: 'Tilkynningar eru lokaðar.', testNotificationError: 'Ekki tókst að senda pruftilkynninguna.', testNotificationTitle: 'Pruftilkynning', testNotificationBody: 'Þetta er Viking Bio-prufutilkynning frá push-PWA.',
  },
};

let uiUrl = (window.location.origin && window.location.origin !== 'null') ? window.location.origin : (window.location.protocol + '//' + window.location.host);
let sendToken = '';
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || ((window.navigator.userAgentData && window.navigator.userAgentData.platform === 'macOS') && navigator.maxTouchPoints > 1) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1);
const HEARTBEAT_INTERVAL_MS = 24 * 60 * 60 * 1000;
const OFFLINE_HEARTBEATS_THRESHOLD = 3;
const DEVICE_OFFLINE_THRESHOLD_MS = HEARTBEAT_INTERVAL_MS * OFFLINE_HEARTBEATS_THRESHOLD;
const installBanner = document.getElementById('install-banner');
const installButton = document.getElementById('install-button');
const yamlGenerator = document.getElementById('yaml-generator');
const themeColorMeta = document.querySelector('meta[name="theme-color"]');
const enablePushButton = document.getElementById('enable-push');
const sendTestButton = document.getElementById('send-test');
const copyButton = document.getElementById('copy-yaml');
const languageSelect = document.getElementById('app-language');
const prioritySelect = document.getElementById('subscription-priority');
const senderInput = document.getElementById('subscription-sender');
const subscriptionYaml = document.getElementById('subscription-yaml');
const statusBox = document.getElementById('status');
const lastContactBox = document.getElementById('last-contact-status');
const rssiBox = document.getElementById('rssi-status');
const lfsBox = document.getElementById('lfs-status');
let installPromptEvent = null;
let lastOfflineNotificationAt = 0;
let currentLanguage = detectLanguage();

function normaliseLanguage(value) {
  const candidate = String(value || '').trim().toLowerCase().replace(/_/g, '-');
  if (!candidate) {
    return DEFAULT_LANGUAGE;
  }

  for (const language of SUPPORTED_LANGUAGES) {
    if ((language.browserCodes || []).some((alias) => candidate.startsWith(alias))) {
      return language.code;
    }
  }

  return DEFAULT_LANGUAGE;
}

function detectLanguage() {
  const search = new URLSearchParams(window.location.search);
  const explicit = search.get('lang');
  if (explicit) {
    return normaliseLanguage(explicit);
  }

  const stored = window.localStorage.getItem('vikingBioLanguage');
  if (stored) {
    return normaliseLanguage(stored);
  }

  const preferred = Array.isArray(navigator.languages) && navigator.languages.length > 0
    ? navigator.languages
    : [navigator.language || DEFAULT_LANGUAGE];
  return normaliseLanguage(preferred[0]);
}

function t(key, replacements = {}) {
  const catalog = MESSAGES[currentLanguage] || MESSAGES[DEFAULT_LANGUAGE];
  const fallback = MESSAGES[DEFAULT_LANGUAGE];
  const template = Object.prototype.hasOwnProperty.call(catalog, key) ? catalog[key] : fallback[key];
  return String(template || '').replace(/\{(\w+)\}/g, (_, name) => String(replacements[name] ?? ''));
}

function syncThemeColor() {
  if (!themeColorMeta) {
    return;
  }

  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  themeColorMeta.content = prefersDark ? '#020817' : '#f8fafc';
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.textContent = value;
  }
}

function setStatus(message, type = '') {
  statusBox.textContent = message;
  statusBox.className = `status ${type}`.trim();
}

function applyTranslations() {
  document.documentElement.lang = currentLanguage;
  document.title = t('pageTitle');
  setText('app-eyebrow', t('eyebrow'));
  setText('app-heading', t('heading'));
  setText('install-title', t('installTitle'));
  setText('install-help', t('installHelp'));
  setText('install-button', t('installButton'));
  setText('language-label', t('languageLabel'));
  setText('sender-label', t('senderLabel'));
  senderInput.placeholder = t('senderPlaceholder');
  senderInput.setAttribute('aria-label', t('senderLabel'));
  setText('notification-levels-label', t('notificationLevels'));
  document.getElementById('notification-levels-group').setAttribute('aria-label', t('notificationLevels'));
  document.getElementById('notification-level-low-label').lastChild.textContent = ` ${t('notificationLevelLow')}`;
  document.getElementById('notification-level-normal-label').lastChild.textContent = ` ${t('notificationLevelNormal')}`;
  document.getElementById('notification-level-high-label').lastChild.textContent = ` ${t('notificationLevelHigh')}`;
  setText('priority-label', t('priorityLabel'));
  if (prioritySelect.options.length >= 3) {
    prioritySelect.options[0].textContent = t('priorityLow');
    prioritySelect.options[1].textContent = t('priorityNormal');
    prioritySelect.options[2].textContent = t('priorityHigh');
  }
  setText('send-test', t('sendTest'));
  setText('yaml-help', t('yamlHelp'));
  setText('enable-push', t('generateYaml'));
  setText('copy-yaml', t('copyYaml'));
  subscriptionYaml.setAttribute('aria-label', t('yamlAria'));
  if (!statusBox.textContent || statusBox.dataset.i18nState === 'waiting') {
    setStatus(t('waitingSubscription'));
    statusBox.dataset.i18nState = 'waiting';
  }
  if (!lastContactBox.dataset.state || lastContactBox.dataset.state === 'waiting') {
    lastContactBox.textContent = t('waitingHeartbeat');
    lastContactBox.dataset.state = 'waiting';
  }
  if (!rssiBox.dataset.state || rssiBox.dataset.state === 'waiting') {
    rssiBox.textContent = t('waitingRssi');
    rssiBox.dataset.state = 'waiting';
  }
  if (!lfsBox.dataset.state || lfsBox.dataset.state === 'waiting') {
    lfsBox.textContent = t('waitingLfs');
    lfsBox.dataset.state = 'waiting';
  }
}

function populateLanguageOptions() {
  languageSelect.innerHTML = '';
  for (const language of SUPPORTED_LANGUAGES) {
    const option = document.createElement('option');
    option.value = language.code;
    option.textContent = language.label;
    option.selected = language.code === currentLanguage;
    languageSelect.appendChild(option);
  }
  languageSelect.setAttribute('aria-label', t('languageLabel'));
}

const colorSchemeMedia = window.matchMedia('(prefers-color-scheme: dark)');
if (typeof colorSchemeMedia.addEventListener === 'function') {
  colorSchemeMedia.addEventListener('change', syncThemeColor);
} else if (typeof colorSchemeMedia.addListener === 'function') {
  colorSchemeMedia.addListener(syncThemeColor);
}
syncThemeColor();
populateLanguageOptions();
applyTranslations();

function notifyOffline(deviceLabel) {
  if (!('Notification' in window) || Notification.permission !== 'granted') {
    return;
  }

  const now = Date.now();
  if (now - lastOfflineNotificationAt < 60 * 60 * 1000) {
    return;
  }

  lastOfflineNotificationAt = now;
  new Notification(t('offlineTitle'), {
    body: t('offlineBody', { device: deviceLabel }),
    tag: `viking-bio-offline-${deviceLabel}`,
    icon: '/icon.svg',
    badge: '/icon.svg',
  });
}

function updateYamlGeneratorVisibility(hasHeartbeat) {
  if (!yamlGenerator) {
    return;
  }

  yamlGenerator.classList.toggle('hidden', hasHeartbeat);
}

function lfsHealthText(value) {
  if (value === null) {
    return t('lfsUnavailable');
  }
  return value ? t('lfsHealthTrue') : t('lfsHealthFalse');
}

async function syncServiceWorkerLanguage() {
  if (!('serviceWorker' in navigator)) {
    return;
  }

  const registration = await navigator.serviceWorker.ready;
  const target = registration.active || navigator.serviceWorker.controller;
  if (target) {
    target.postMessage({ type: 'set-language', language: currentLanguage });
  }
}

function applyHeartbeatUpdate(payload) {
  if (!payload || payload.type !== 'heartbeat') {
    return;
  }

  const rssiValue = Number.isFinite(Number(payload.rssi)) ? Number(payload.rssi) : null;
  const lfsHealth = Object.prototype.hasOwnProperty.call(payload, 'lfsHealth') ? payload.lfsHealth : null;
  const rawTimestamp = Number(payload.timestamp);
  const stamp = Number.isFinite(rawTimestamp) ? new Date(rawTimestamp) : new Date();
  const label = Number.isNaN(stamp.getTime()) ? t('unknownTime') : stamp.toLocaleString();

  lastContactBox.textContent = t('lastContact', { label });
  lastContactBox.dataset.state = 'data';
  rssiBox.textContent = rssiValue === null ? t('rssiUnavailable') : t('rssiValue', { value: rssiValue });
  rssiBox.dataset.state = 'data';
  lfsBox.textContent = lfsHealthText(lfsHealth);
  lfsBox.dataset.state = 'data';
}

async function loadLastContactStatus() {
  try {
    const response = await fetch('/status.php', { headers: { Accept: 'application/json' } });
    if (!response.ok) {
      throw new Error(t('loadHeartbeatError'));
    }

    const data = await response.json();
    const devices = data && typeof data.devices === 'object' ? Object.values(data.devices) : [];
    const selectedSender = (senderInput.value || '').trim();
    const selectedDevice = selectedSender
      ? devices.find((device) => String(device.device || '').toLowerCase() === selectedSender.toLowerCase())
      : null;
    const lastContact = selectedDevice ? selectedDevice.timestamp : data.lastContact;
    const rssiValue = selectedDevice && Number.isFinite(Number(selectedDevice.rssi))
      ? Number(selectedDevice.rssi)
      : (Number.isFinite(Number(data.lastRssi)) ? Number(data.lastRssi) : null);
    const lfsHealth = selectedDevice && Object.prototype.hasOwnProperty.call(selectedDevice, 'lfsHealth')
      ? selectedDevice.lfsHealth
      : data.lastLfsHealth;

    if (!lastContact || !Number.isFinite(Number(lastContact))) {
      lastContactBox.textContent = t('noHeartbeatYet');
      lastContactBox.dataset.state = 'data';
      rssiBox.textContent = t('rssiUnavailable');
      rssiBox.dataset.state = 'data';
      lfsBox.textContent = t('lfsUnavailable');
      lfsBox.dataset.state = 'data';
      updateYamlGeneratorVisibility(false);
      return;
    }

    const contactTimestamp = Number(lastContact);
    updateYamlGeneratorVisibility(true);
    const isOffline = Date.now() - contactTimestamp > DEVICE_OFFLINE_THRESHOLD_MS;
    if (isOffline) {
      const deviceLabel = selectedDevice && selectedDevice.device ? selectedDevice.device : t('bridgeDevice');
      lastContactBox.textContent = t('offlineBody', { device: deviceLabel });
      lastContactBox.dataset.state = 'data';
      rssiBox.textContent = rssiValue === null ? t('rssiUnavailable') : t('rssiValue', { value: rssiValue });
      rssiBox.dataset.state = 'data';
      lfsBox.textContent = lfsHealthText(lfsHealth);
      lfsBox.dataset.state = 'data';
      notifyOffline(deviceLabel);
      return;
    }

    const stamp = new Date(contactTimestamp);
    const label = Number.isNaN(stamp.getTime()) ? t('unknownTime') : stamp.toLocaleString();
    lastContactBox.textContent = t('lastContact', { label });
    lastContactBox.dataset.state = 'data';
    rssiBox.textContent = rssiValue === null ? t('rssiUnavailable') : t('rssiValue', { value: rssiValue });
    rssiBox.dataset.state = 'data';
    lfsBox.textContent = lfsHealthText(lfsHealth);
    lfsBox.dataset.state = 'data';
  } catch (error) {
    lastContactBox.textContent = t('heartbeatUnavailable');
    lastContactBox.dataset.state = 'data';
    rssiBox.textContent = t('rssiUnavailable');
    rssiBox.dataset.state = 'data';
    lfsBox.textContent = t('lfsUnavailable');
    lfsBox.dataset.state = 'data';
  }
}

async function loadConfig() {
  const response = await fetch('/config.php', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(t('loadConfigError'));
  }

  const config = await response.json();
  uiUrl = config.uiUrl || uiUrl;
  sendToken = config.sendToken || sendToken;
  return config;
}

async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) {
    throw new Error(t('serviceWorkerUnsupported'));
  }

  if (!navigator.serviceWorker.controller) {
    await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  }

  await syncServiceWorkerLanguage();

  navigator.serviceWorker.addEventListener('message', (event) => {
    const payload = event.data && typeof event.data === 'object' ? (event.data.payload || event.data) : null;
    if (payload && payload.type === 'heartbeat') {
      applyHeartbeatUpdate(payload);
    }
  });
}

async function fetchPublicKey() {
  const response = await fetch('/public-key.php', { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(t('vapidFetchError'));
  }

  const data = await response.json();
  if (!data.publicKey) {
    throw new Error(t('vapidMissing'));
  }

  return data.publicKey;
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);

  for (let index = 0; index < raw.length; index += 1) {
    output[index] = raw.charCodeAt(index);
  }

  return output;
}

function getNotificationLevels() {
  return {
    low: document.getElementById('notification-level-low').checked,
    normal: document.getElementById('notification-level-normal').checked,
    high: document.getElementById('notification-level-high').checked,
  };
}

function buildSubscriptionYaml(subscription) {
  const keys = subscription.toJSON ? subscription.toJSON().keys : subscription.keys || {};
  const sender = (senderInput.value || '').trim();
  return {
    subscriptions: [{
      endpoint: subscription.endpoint,
      keys: {
        p256dh: keys.p256dh || '',
        auth: keys.auth || '',
      },
      sender,
      language: currentLanguage,
      notificationLevel: getNotificationLevels(),
      uiUrl,
    }],
  };
}

async function enableNotifications() {
  try {
    setStatus(t('loadingConfig'));
    statusBox.dataset.i18nState = 'custom';
    await loadConfig();

    setStatus(t('registerServiceWorker'));
    await registerServiceWorker();

    if (!('PushManager' in window)) {
      throw new Error(t('pushUnsupported'));
    }

    let permission = Notification.permission;
    if (permission === 'default') {
      setStatus(t('requestPermission'));
      permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        throw new Error(t('permissionDenied'));
      }
    }

    if (permission !== 'granted') {
      throw new Error(t('notificationsBlocked'));
    }

    const publicKey = await fetchPublicKey();
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(publicKey),
    });

    const payload = buildSubscriptionYaml(subscription);
    subscriptionYaml.value = JSON.stringify(payload, null, 2);
    setStatus(t('generatedYaml'), 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

async function sendTestAlert() {
  try {
    if (!sendToken) {
      await loadConfig();
    }

    const permission = Notification.permission;
    if (permission !== 'granted') {
      throw new Error(t('permissionBeforeTest'));
    }

    const sender = (senderInput.value || '').trim();
    const response = await fetch('/send.php', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + sendToken,
      },
      body: JSON.stringify({
        type: 'test_alert',
        title: t('testNotificationTitle'),
        body: t('testNotificationBody'),
        sender,
        language: currentLanguage,
        priority: prioritySelect.value,
        url: uiUrl,
      }),
    });

    if (!response.ok) {
      throw new Error(t('testNotificationError'));
    }

    const data = await response.json();
    setStatus(t('sentCount', { count: data.sent }), 'success');
  } catch (error) {
    setStatus(error.message, 'error');
  }
}

copyButton.addEventListener('click', async () => {
  if (!subscriptionYaml.value.trim()) {
    setStatus(t('generateBeforeCopy'), 'error');
    return;
  }

  await navigator.clipboard.writeText(subscriptionYaml.value);
  setStatus(t('copiedYaml'), 'success');
});

languageSelect.addEventListener('change', async () => {
  currentLanguage = normaliseLanguage(languageSelect.value);
  window.localStorage.setItem('vikingBioLanguage', currentLanguage);
  populateLanguageOptions();
  applyTranslations();
  await syncServiceWorkerLanguage();
  await loadLastContactStatus();
});

if (isIOS && !window.matchMedia('(display-mode: standalone)').matches) {
  installBanner.classList.remove('hidden');
}

loadLastContactStatus();
window.setInterval(loadLastContactStatus, 30000);

window.addEventListener('beforeinstallprompt', (event) => {
  event.preventDefault();
  installPromptEvent = event;
  if (!isIOS) {
    installBanner.classList.remove('hidden');
  }
});

installButton.addEventListener('click', async () => {
  if (isIOS) {
    setStatus(t('useSafariInstall'));
    return;
  }

  if (!installPromptEvent) {
    setStatus(t('installPromptMissing'), 'error');
    return;
  }

  installPromptEvent.prompt();
  await installPromptEvent.userChoice;
  installBanner.classList.add('hidden');
});

enablePushButton.addEventListener('click', enableNotifications);
sendTestButton.addEventListener('click', sendTestAlert);
