import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://phieri.github.io',
  base: '/viking-bio-pwa',
  output: 'static',
  trailingSlash: 'always',
});
