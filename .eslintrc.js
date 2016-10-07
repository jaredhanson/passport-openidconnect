module.exports = {
  extends: 'auth0',
  installedESLint: true,
  env: {
    node: true,
    mocha: true,
    es6: false
  },
  parserOptions: {
    ecmaVersion: 5,
    ecmaFeatures: {
      arrowFunctions: false
    },
  },
  rules: {
    'no-unused-vars': ['error', {args: 'none'}],
    'object-shorthand': ['error', 'never'],
    'no-confusing-arrow': 'error',

    // Rules set to warning because they are not followed but should be in the future.
    'max-len': 'warn',
    'no-caller': 'warn',
    'no-mixed-operators': 'warn',
    'quote-props': 'warn',

    // Rules turned off because they are not followed.
    'block-scoped-var': 'off',
    'consistent-return': 'off',
    'eqeqeq': 'off',
    'func-names': 'off',
    'guard-for-in': 'off',
    'no-else-return': 'off',
    'no-param-reassign': 'off',
    'no-restricted-syntax': 'off',
    'no-shadow': 'off',
    'no-underscore-dangle': 'off',
    'no-var': 'off',
    'one-var': 'off',
    'prefer-arrow-callback': 'off',
    'prefer-template': 'off',
    'vars-on-top': 'off',
    'no-proto': 'off'
  }
};
