// Tailwind CSS v4 is wired in through its own PostCSS plugin. v4 performs
// vendor prefixing internally, so autoprefixer is not needed alongside it.
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
