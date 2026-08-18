/** @type {import('postcss-load-config').Config} */
export default {
  plugins: {
    // Tailwind 4 moved the PostCSS plugin out of the main package.
    // Autoprefixer is no longer needed — v4 handles vendor prefixing itself.
    '@tailwindcss/postcss': {},
  },
};
