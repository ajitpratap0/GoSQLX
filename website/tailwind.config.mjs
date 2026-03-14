/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: '#1e293b',
        elevated: '#334155',
        'accent-orange': '#f97316',
        'accent-blue': '#3b82f6',
        'accent-green': '#22c55e',
        'accent-purple': '#a78bfa',
      },
      fontFamily: {
        code: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        body: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};
