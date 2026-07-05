/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          orange: '#FE5729',
          black: '#1C1C1C',
          paper: '#F1F1F1',
          peach: '#FFBC99',
          violet: '#D4B5FF',
          green: '#2EB679',
        },
      },
    },
  },
  plugins: [],
};
