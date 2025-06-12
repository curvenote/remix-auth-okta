/* eslint-disable unicorn/prefer-module */
export default {
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:unicorn/recommended",
    "prettier",
  ],
  plugins: ["@typescript-eslint", "unicorn", "prettier"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
  },
  env: {
    es2022: true,
    node: true,
  },
  rules: {
    "prettier/prettier": "error",
    "unicorn/prefer-module": "off",
    "unicorn/prefer-node-protocol": "off",
  },
};
