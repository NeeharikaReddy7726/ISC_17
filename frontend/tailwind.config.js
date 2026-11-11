/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          950: "#060914",
          900: "#0B1120",
          800: "#11192E",
          700: "#18233F"
        }
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"]
      },
      boxShadow: {
        cyber: "0 0 30px -8px rgba(59, 130, 246, 0.25)",
        panel: "0 12px 32px -12px rgba(2, 6, 23, 0.75)"
      }
    }
  },
  plugins: []
};
