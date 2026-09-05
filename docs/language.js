(function () {
  function getPreferredLanguage() {
    return navigator.language && navigator.language.toLowerCase().startsWith('sv') ? 'sv' : 'en';
  }

  function applyTranslations(lang) {
    const selectedLang = lang === 'sv' ? 'sv' : 'en';
    const views = document.querySelectorAll('[data-language-view]');

    views.forEach(function (view) {
      view.hidden = view.dataset.languageView !== selectedLang;
    });

    const navLabels = {
      en: {
        overview: 'Overview',
        features: 'Features',
        architecture: 'Architecture',
        project: 'Project'
      },
      sv: {
        overview: 'Översikt',
        features: 'Funktioner',
        architecture: 'Arkitektur',
        project: 'Projekt'
      }
    };

    document.querySelectorAll('.nav-links a').forEach(function (link) {
      const key = link.dataset.nav;
      if (!key) {
        return;
      }

      link.textContent = navLabels[selectedLang][key];
      if (selectedLang === 'sv') {
        link.setAttribute('href', link.dataset.hrefSv || link.getAttribute('href'));
      } else {
        link.setAttribute('href', '#' + key);
      }
    });

    const footerBrand = document.querySelector('[data-footer-brand]');
    if (footerBrand) {
      footerBrand.textContent = 'Viking Bio Integration';
    }

    const githubLink = document.querySelector('[data-github-aria]');
    if (githubLink) {
      const labels = {
        en: 'Viking Bio project on GitHub (opens in new tab)',
        sv: 'Viking Bio-projekt på GitHub (öppnas i ny flik)'
      };
      githubLink.setAttribute('aria-label', labels[selectedLang]);
      githubLink.textContent = 'GitHub';
    }

    document.querySelectorAll('[data-source-aria]').forEach(function (link) {
      const labels = {
        en: 'View source on GitHub (opens in new tab)',
        sv: 'Visa källkod på GitHub (öppnas i ny flik)'
      };
      link.setAttribute('aria-label', labels[selectedLang]);
    });

    document.documentElement.lang = selectedLang;

    const metaDescription = document.querySelector('meta[name="description"]');
    if (metaDescription) {
      metaDescription.setAttribute(
        'content',
        selectedLang === 'sv'
          ? 'Viking Bio-integration för att övervaka och hantera telemetri från pelletsbrännare med en Pico-baserad brygga och lokal konfigurator.'
          : 'Viking Bio integration for monitoring and managing pellet burner telemetry with a Pico-based bridge and local configurator.'
      );
    }
  }

  applyTranslations(getPreferredLanguage());
})();
