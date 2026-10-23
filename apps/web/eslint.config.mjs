// eslint-config-next 16 ships native ESLint flat config, so it is spread in
// directly. FlatCompat is not used: it targets the old eslintrc format and
// fails on these already-flat config objects.
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const config = [
  {
    ignores: [".next/**", "node_modules/**", "next-env.d.ts"],
  },
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    rules: {
      // An unused variable is usually a leftover, but a leading underscore is
      // a deliberate signal that a value is intentionally ignored.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
];

export default config;
