// eslint.config.js — ESLint v10 flat config
// Uses @typescript-eslint/eslint-plugin + @typescript-eslint/parser
// which are the packages already installed in package.json.
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    // Source files: type-aware linting via root tsconfig
    files: ["shared/**/*.ts", "send/**/*.ts", "receive/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: {
      ...tsPlugin.configs["recommended"].rules,
      // Non-null assertions are used extensively in the original codebase for
      // proven-safe typed-array accesses under noUncheckedIndexedAccess.
      // Warn rather than error so CI stays green on existing code.
      "@typescript-eslint/no-non-null-assertion": "warn",
      // Unhandled floating promises are a real bug risk in browser handlers.
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  {
    // Test files: no project-based type-aware linting
    // (tsconfig.test.json is separate; mixing both causes parser conflicts).
    // Type-checking of tests is handled by `npm run typecheck` via tsc.
    files: ["tests/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: { project: null },
    },
    plugins: { "@typescript-eslint": tsPlugin },
    rules: {
      ...tsPlugin.configs["recommended"].rules,
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-floating-promises": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  {
    ignores: ["node_modules/**", "dist/**", "vitest.config.ts", "vite.config.ts"],
  },
];
