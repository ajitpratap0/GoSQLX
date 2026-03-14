/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: '#1e293b',
        elevated: '#334155',
        deeper: '#0c1322',
        code: '#0d1117',
        'accent-orange': '#f97316',
        'accent-blue': '#3b82f6',
        'accent-green': '#22c55e',
        'accent-purple': '#a78bfa',
      },
      fontFamily: {
        code: ['"JetBrains Mono"', 'monospace'],
        body: ['"Instrument Sans"', 'system-ui', 'sans-serif'],
        heading: ['"IBM Plex Mono"', 'monospace'],
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};
