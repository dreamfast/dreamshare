// Flat config, blocking rules only, with one sanctioned exception: the
// share body renders sanitised markdown through v-html at exactly one call
// site.
import eslint from '@eslint/js'
import tseslint from 'typescript-eslint'
import pluginVue from 'eslint-plugin-vue'
import globals from 'globals'

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  ...pluginVue.configs['flat/essential'],
  {
    files: ['**/*.{ts,vue,js}'],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
  {
    // vue files parse the template, the script block hands off to tsc's
    // parser so typescript rules apply inside sfc scripts too
    files: ['**/*.vue'],
    languageOptions: { parserOptions: { parser: tseslint.parser } },
  },
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'vue/multi-word-component-names': 'off',
      'vue/no-v-html': 'error',
      // logic rules from the recommended set, the formatting half is
      // prettier's job and the two would fight
      'vue/no-unused-refs': 'error',
      'vue/require-explicit-emits': 'error',
      'vue/no-mutating-props': 'error',
      'vue/no-side-effects-in-computed-properties': 'error',
    },
  },
  {
    // the two sanctioned html sinks: the sanitised markdown output in the
    // share view and the locally generated qr svg in the uploaded view.
    // Both are named to keep the ignore pattern tight.
    files: [
      'src/views/Share.vue',
      'src/views/Uploaded.vue',
      'src/views/Terms.vue',
      'src/views/Privacy.vue',
      'src/views/Composer.vue',
    ],
    rules: {
      'vue/no-v-html': ['error', { ignorePattern: '^(bodyHtml|qrSvg|legalHtml|msgPreviewHtml)$' }],
    },
  },
  {
    files: ['**/*.test.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-function-type': 'off',
    },
  },
)
