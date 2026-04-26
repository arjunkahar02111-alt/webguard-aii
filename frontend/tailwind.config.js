/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg:      "#040506",
        bg2:     "#0a0d14",
        bg3:     "#121822",
        accent:  "#00d4aa",   // neon green
        accent2: "#007aff",   // electric blue
        danger:  "#ff2d55",
        warn:    "#ffaa00"
      },
      fontFamily: {
        mono: ['"Space Mono"', "monospace"],
        sans: ['"Inter"', '"Space Grotesk"', "system-ui", "sans-serif"],
      },
      backgroundImage: {
        'cyber-grid': 'linear-gradient(rgba(0, 212, 170, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 212, 170, 0.05) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 212, 170, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 212, 170, 0.6)' }
        }
      }
    },
  },
  plugins: [],
};
