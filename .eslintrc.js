module.exports = {
  extends: 'auth0',
  installedESLint: true,
  env: {
    node: true
  },
  parserOptions: {
    ecmaVersion: 5
  },
  rules: {
    'no-unused-vars': ['error', {args: 'none'}],

    // Rules set to warning because they are not followed but should be in the future.
    'max-len': 'warn',
    'no-mixed-operators': 'warn',
    'quote-props': 'warn',

    // Rules turned off because they are not followed.
    'block-scoped-var': 'off',
    'consistent-return': 'off',
    'dot-notation': 'off',
    'eqeqeq': 'off',
    'guard-for-in': 'off',
    'keyword-spacing': 'off',
    'no-else-return': 'off',
    'no-param-reassign': 'off',
    'no-restricted-syntax': 'off',
    'no-shadow': 'off',
    'no-underscore-dangle': 'off',
    'no-var': 'off',
    'object-shorthand': 'off',
    'one-var': 'off',
    'padded-blocks': 'off',
    'prefer-arrow-callback': 'off',
    'prefer-template': 'off',
    'space-before-blocks': 'off',
    'space-before-function-paren': 'off',
    'spaced-comment': 'off',
    'vars-on-top': 'off',
    'no-caller': 'off',
    'no-proto': 'off',
    'brace-style': 'off',
  }
};
