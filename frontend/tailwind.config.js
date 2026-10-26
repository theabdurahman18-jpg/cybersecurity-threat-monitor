/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#030712',
          card: '#0B132B',
          border: '#1C2541',
          cyan: '#00F0FF',
          magenta: '#FF0055',
          amber: '#FFB800',
          green: '#00FF66',
          purple: '#7928CA'
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'monospace'],
        display: ['"Orbitron"', 'sans-serif'],
        sans: ['"Rajdhani"', 'sans-serif']
      },
      animation: {
        'pulse-fast': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 240, 255, 0.4)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 240, 255, 0.8)' }
        }
      }
    },
  },
  plugins: [],
}
