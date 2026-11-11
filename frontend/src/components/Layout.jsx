import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  FileCheck2,
  History,
  LogOut,
  Menu,
  QrCode,
  Shield,
  ShieldCheck,
  UserCircle2,
  X
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

const NAV_ITEMS = [
  { to: "/dashboard", label: "QR Scanner", Icon: QrCode },
  { to: "/results", label: "Scan Results", Icon: FileCheck2 },
  { to: "/history", label: "Scan History", Icon: History }
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  function handleLogout() {
    logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex min-h-screen flex-col">
      {/* Top Cybersecurity Header */}
      <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-navy-950/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          {/* Brand Logo */}
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              className="rounded-lg border border-slate-800 bg-navy-900 p-2 text-slate-300 hover:text-white md:hidden"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>

            <NavLink to="/dashboard" className="flex items-center gap-2.5 group">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-blue-500/20 to-violet-500/25 border border-indigo-500/40 shadow-cyber">
                <Shield className="h-5 w-5 text-sky-400" />
              </div>
              <div>
                <span className="block text-base font-bold tracking-tight text-white">
                  QR <span className="text-sky-400">Shield</span>
                </span>
                <span className="hidden text-[11px] font-medium tracking-wider text-slate-400 sm:block">
                  AI PHISHING &amp; CRYPTO SCANNER
                </span>
              </div>
            </NavLink>
          </div>

          {/* Desktop Navigation Pills */}
          <nav className="hidden items-center gap-1.5 md:flex">
            {NAV_ITEMS.map(({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition ${
                    isActive
                      ? "bg-gradient-to-r from-blue-600/25 to-violet-600/25 text-white border border-indigo-500/40"
                      : "text-slate-400 hover:bg-navy-800/80 hover:text-slate-100 border border-transparent"
                  }`
                }
              >
                <Icon className="h-4 w-4" />
                {label}
              </NavLink>
            ))}
          </nav>

          {/* User Identity & Logout */}
          <div className="flex items-center gap-3">
            {user && (
              <div className="hidden items-center gap-2 rounded-full border border-slate-800 bg-navy-900 px-3 py-1.5 text-xs text-slate-300 sm:flex">
                <UserCircle2 className="h-4 w-4 text-indigo-400" />
                <span className="max-w-[180px] truncate font-medium">{user.email}</span>
              </div>
            )}

            <button
              type="button"
              onClick={handleLogout}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-navy-900 px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-rose-500/50 hover:bg-rose-500/10 hover:text-rose-200"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Logout</span>
            </button>
          </div>
        </div>

        {/* Mobile Drawer Navigation */}
        {mobileMenuOpen && (
          <div className="border-t border-slate-800 bg-navy-900 px-4 py-3 md:hidden">
            {user && (
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-slate-800 bg-navy-950 px-3 py-2 text-xs text-slate-300">
                <UserCircle2 className="h-4 w-4 text-indigo-400" />
                <span className="truncate font-medium">{user.email}</span>
              </div>
            )}
            <nav className="flex flex-col gap-1">
              {NAV_ITEMS.map(({ to, label, Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setMobileMenuOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition ${
                      isActive
                        ? "bg-gradient-to-r from-blue-600/25 to-violet-600/25 text-white border border-indigo-500/40"
                        : "text-slate-300 hover:bg-navy-800"
                    }`
                  }
                >
                  <Icon className="h-4 w-4" />
                  {label}
                </NavLink>
              ))}
            </nav>
          </div>
        )}
      </header>

      {/* Main Content Workspace */}
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
        <Outlet />
      </main>

      {/* Subtle Security Architecture Footer */}
      <footer className="border-t border-slate-800/60 bg-navy-950/60 py-4 text-xs text-slate-500">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-2 px-4 sm:flex-row sm:px-6 lg:px-8">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-indigo-400" />
            <span>QR Shield Security Suite • Static Inspection Only (No Auto-Navigation)</span>
          </div>
          <span className="font-mono text-[11px] text-slate-500">
            OpenCV • Random Forest ML • Argon2/JWT • SHA-256 + AES-256-GCM
          </span>
        </div>
      </footer>
    </div>
  );
}
