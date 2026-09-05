const fs = require('fs');
const path = require('path');

const root = __dirname;
const outputDir = path.join(root, 'en');
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
    ctaExplore: 'Explore the project',
    ctaSource: 'View source',
    sourceAria: 'View source on GitHub (opens in new tab)',
    panelLabel: 'Telemetry flow',
    panelConfigurator: 'Local configurator',
    panelItem1: 'UART capture from burner output',
    panelItem2: 'Signed TCP stream to local runtime',
    panelItem3: 'Local configuration and status UI',
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
      'The project is designed to surface burner state and fault information in a way that is easy to inspect from a local dashboard or on-device configuration flow.',
    featuresEyebrow: 'Features',
    featuresTitle: 'Everything needed to make a burner smarter without losing control',
    featureTelemetryTitle: 'Signed telemetry',
    featureTelemetryBody:
      'Each message is authenticated with a device key so the local server can verify incoming burner data.',
    featureUSBTitle: 'USB provisioning',
    featureUSBBody:
      'Bridge setup can happen over serial with a GUI or terminal-based configurator, making installation straightforward.',
    featureNetworkTitle: 'Local network-first design',
    featureNetworkBody:
      'The runtime is built around a local device-first deployment model instead of an externally hosted dashboard.',
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
      'The system separates the hardware-facing bridge from the local monitoring/configuration runtime. The Pico reads burner data and streams signed telemetry to a Go process on the same trusted local network. That Go process owns the UI, services, and configuration flow while the bridge stays focused on measurement and delivery.',
    stack1: 'Burner serial data',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signed TCP ingest',
    stack4: 'Go runtime + local APIs',
    stack5: 'Operator dashboard / config UI',
    projectEyebrow: 'Project',
    projectTitle: 'Built for owners, integrators, and makers who want a practical burner monitor',
    projectBody1:
      'This repository is a complete integration project for the Viking Bio 20 pellet burner: firmware, protocol parsing, local runtime, and browser-based status UI and configuration tooling. It is designed to be understandable, extensible, and easy to run on a small local device or home network.',
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
    ctaExplore: 'Utforska projektet',
    ctaSource: 'Visa källkod',
    sourceAria: 'Visa källkod på GitHub (öppnas i ny flik)',
    panelLabel: 'Telemetriflöde',
    panelConfigurator: 'Lokal konfigurator',
    panelItem1: 'UART-avläsning från brännaren',
    panelItem2: 'Signerad TCP-ström till lokal runtime',
    panelItem3: 'Lokal konfigurations- och statusvy',
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
      'Projektet är designat för att visa brännarens tillstånd och fel i ett format som enkelt kan inspekteras via en lokal dashboard eller den lokala konfigurationsvyn.',
    featuresEyebrow: 'Funktioner',
    featuresTitle: 'Allt som behövs för att göra en brännare smartare utan att förlora kontrollen',
    featureTelemetryTitle: 'Signerad telemetri',
    featureTelemetryBody:
      'Varje meddelande autentiseras med en enhetsnyckel så att den lokala servern kan verifiera inkommande data.',
    featureUSBTitle: 'USB-installation',
    featureUSBBody:
      'Bryggkonfiguration kan ske över seriell port med GUI eller terminalbaserad konfigurator, vilket gör installationen enkel.',
    featureNetworkTitle: 'Lokal nätverks-first design',
    featureNetworkBody:
      'Runtime är byggt kring en lokal, enhetscentrerad design i stället för en externt hostad dashboard.',
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
      'Systemet separerar hårdvarunära bryggan från lokal övervakning och konfiguration. Pico läser brännardata och strömmar signerad telemetri till en Go-process i samma lokala nätverk. Den processen äger användargränssnitt, tjänster och konfigurationsflöde medan bryggan fokuserar på mätning och leverans.',
    stack1: 'Seriedata från brännaren',
    stack2: 'Pico W / Pico 2 W firmware',
    stack3: 'Signerad TCP-ingest',
    stack4: 'Go runtime + lokala API:er',
    stack5: 'Operatörspanel / konfigurationsgränssnitt',
    projectEyebrow: 'Projekt',
    projectTitle: 'Byggt för ägare, installatörer och skapare som vill ha en praktisk brännarmonitor',
    projectBody1:
      'Det här repo:t är ett komplett integrationsprojekt för Viking Bio 20-pelletbrännaren: firmware, protokollanalys, lokal runtime och webb-baserat statusgränssnitt för konfiguration. Det är designat för att vara lätt att förstå, utöka och köra på liten lokal utrustning i hemmet.',
    projectBody2:
      'Fokus ligger på ärlig driftkontroll: håll data lokalt, verifiera enheten i kanten och erbjuda ett pålitligt konfigurationsflöde utan att vara beroende av en hostad produkt eller molnbackend.',
    footerBrand: 'Viking Bio Integration',
    footerGitHub: 'GitHub'
  }
};

function renderPage(data, variant) {
  const nav = data.nav
    .map((label, index) => {
      const anchors = ['overview', 'features', 'architecture', 'project'];
      const href = variant === 'en' ? `#${anchors[index]}` : `#${anchors[index]}`;
      return `<a href="${href}">${label}</a>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="${data.lang}">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="${data.metaDescription}" />
    <title>${data.title}</title>
    <link rel="icon" type="image/svg+xml" href="./favicon.svg" />
    <link rel="stylesheet" href="./styles.css" />
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
            <p class="eyebrow">${data.heroEyebrow}</p>
            <h1>${data.heroTitle}</h1>
            <p class="lead">${data.heroLead}</p>
            <div class="cta-row">
              <a class="button primary" href="#overview">${data.ctaExplore}</a>
              <a
                class="button secondary"
                href="https://github.com/phieri/viking-bio-pwa"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="${data.sourceAria}"
              >
                ${data.ctaSource}
              </a>
            </div>
          </div>
          <div class="hero-panel">
            <div class="panel-card">
              <span class="panel-label">${data.panelLabel}</span>
              <div class="flow-block">
                <span>Viking Bio 20</span>
                <span class="arrow">→</span>
                <span>Pico W</span>
                <span class="arrow">→</span>
                <span>${data.panelConfigurator}</span>
              </div>
              <ul>
                <li>${data.panelItem1}</li>
                <li>${data.panelItem2}</li>
                <li>${data.panelItem3}</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      <section id="overview" class="section">
        <div class="container">
          <div class="section-heading">
            <p class="eyebrow">${data.overviewEyebrow}</p>
            <h2>${data.overviewTitle}</h2>
          </div>
          <div class="cards three-up">
            <article class="info-card">
              <h3>${data.cardBridgeTitle}</h3>
              <p>${data.cardBridgeBody}</p>
            </article>
            <article class="info-card">
              <h3>${data.cardControlTitle}</h3>
              <p>${data.cardControlBody}</p>
            </article>
            <article class="info-card">
              <h3>${data.cardInsightTitle}</h3>
              <p>${data.cardInsightBody}</p>
            </article>
          </div>
        </div>
      </section>

      <section id="features" class="section alt">
        <div class="container">
          <div class="section-heading narrow">
            <p class="eyebrow">${data.featuresEyebrow}</p>
            <h2>${data.featuresTitle}</h2>
          </div>

          <div class="feature-list">
            <div class="feature-item">
              <h3>${data.featureTelemetryTitle}</h3>
              <p>${data.featureTelemetryBody}</p>
            </div>
            <div class="feature-item">
              <h3>${data.featureUSBTitle}</h3>
              <p>${data.featureUSBBody}</p>
            </div>
            <div class="feature-item">
              <h3>${data.featureNetworkTitle}</h3>
              <p>${data.featureNetworkBody}</p>
            </div>
            <div class="feature-item">
              <h3>${data.featureMDNSTitle}</h3>
              <p>${data.featureMDNSBody}</p>
            </div>
            <div class="feature-item">
              <h3>${data.featureStateTitle}</h3>
              <p>${data.featureStateBody}</p>
            </div>
            <div class="feature-item">
              <h3>${data.featureHardwareTitle}</h3>
              <p>${data.featureHardwareBody}</p>
            </div>
          </div>
        </div>
      </section>

      <section id="architecture" class="section">
        <div class="container architecture-grid">
          <div>
            <p class="eyebrow">${data.architectureEyebrow}</p>
            <h2>${data.architectureTitle}</h2>
            <p>${data.architectureBody}</p>
          </div>
          <div class="stack">
            <div class="stack-item"><span>1</span><span>${data.stack1}</span></div>
            <div class="stack-item"><span>2</span><span>${data.stack2}</span></div>
            <div class="stack-item"><span>3</span><span>${data.stack3}</span></div>
            <div class="stack-item"><span>4</span><span>${data.stack4}</span></div>
            <div class="stack-item"><span>5</span><span>${data.stack5}</span></div>
          </div>
        </div>
      </section>

      <section id="project" class="section alt" aria-labelledby="project-title">
        <div class="container">
          <div class="project-panel">
            <div>
              <p class="eyebrow">${data.projectEyebrow}</p>
              <h2 id="project-title">${data.projectTitle}</h2>
            </div>
            <div class="project-copy">
              <p>${data.projectBody1}</p>
              <p>${data.projectBody2}</p>
            </div>
          </div>
        </div>
      </section>
    </main>

    <footer class="footer">
      <div class="container footer-row">
        <span>${data.footerBrand}</span>
        <a href="https://github.com/phieri/viking-bio-pwa" target="_blank" rel="noopener noreferrer" aria-label="${data.sourceAria}">${data.footerGitHub}</a>
      </div>
    </footer>
  </body>
</html>`;
}

const redirectPage = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Viking Bio Integration</title>
    <script>
      (function () {
        var preferred = navigator.language && navigator.language.toLowerCase().indexOf('sv') === 0 ? 'sv' : 'en';
        window.location.replace(preferred === 'sv' ? './sv/' : './en/');
      })();
    </script>
  </head>
  <body></body>
</html>`;

fs.mkdirSync(outputDir, { recursive: true });
fs.mkdirSync(swedishDir, { recursive: true });
fs.writeFileSync(path.join(outputDir, 'index.html'), renderPage(pages.en, 'en'));
fs.writeFileSync(path.join(swedishDir, 'index.html'), renderPage(pages.sv, 'sv'));
fs.writeFileSync(path.join(root, 'index.html'), redirectPage);

console.log('Generated docs/en/index.html and docs/sv/index.html');
