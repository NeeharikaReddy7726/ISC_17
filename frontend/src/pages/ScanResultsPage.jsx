import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Fingerprint,
  History,
  Info,
  QrCode,
  ShieldAlert,
  ShieldCheck
} from "lucide-react";
import { LAST_SCAN_STORAGE_KEY } from "../context/AuthContext";
import { PredictionBadge, RiskLevelBadge } from "../components/RiskBadge";
import SafeUrlBox from "../components/SafeUrlBox";

const RISK_BANNER_STYLES = {
  Safe: {
    border: "border-emerald-500/35 bg-emerald-500/10",
    iconColor: "text-emerald-400",
    barColor: "bg-emerald-500",
    Icon: ShieldCheck,
    summary: "No phishing indicators detected by the Random Forest model."
  },
  Suspicious: {
    border: "border-amber-500/35 bg-amber-500/10",
    iconColor: "text-amber-400",
    barColor: "bg-amber-500",
    Icon: AlertTriangle,
    summary: "Suspicious URL characteristics detected. Treat with caution."
  },
  "High Risk": {
    border: "border-rose-500/40 bg-rose-500/10",
    iconColor: "text-rose-400",
    barColor: "bg-rose-500",
    Icon: ShieldAlert,
    summary: "High phishing risk detected. Do NOT visit or submit credentials on this URL."
  }
};

export default function ScanResultsPage() {
  const location = useLocation();

  let scanResult = location.state?.scanResult || null;
  if (!scanResult) {
    try {
      const cached = sessionStorage.getItem(LAST_SCAN_STORAGE_KEY);
      if (cached) {
        scanResult = JSON.parse(cached);
      }
    } catch {
      scanResult = null;
    }
  }

  useEffect(() => {
    if (location.state?.scanResult) {
      sessionStorage.setItem(LAST_SCAN_STORAGE_KEY, JSON.stringify(location.state.scanResult));
    }
  }, [location.state]);

  if (!scanResult) {
    return (
      <div className="mx-auto max-w-2xl rounded-2xl border border-slate-800 bg-navy-900/90 p-8 text-center shadow-panel">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-700 bg-navy-950 text-slate-400">
          <QrCode className="h-7 w-7" />
        </div>
        <h1 className="text-xl font-bold text-white">No Active Scan Result</h1>
        <p className="mt-2 text-sm text-slate-400">
          Upload a QR code image from the scanner to view ML classification, confidence, and risk warnings, or inspect an encrypted record from your history.
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2.5 text-sm font-semibold text-white shadow-cyber transition hover:from-blue-500 hover:to-violet-500"
          >
            <QrCode className="h-4 w-4" />
            Go to QR Scanner
          </Link>
          <Link
            to="/history"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-navy-800 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:border-indigo-500/50"
          >
            <History className="h-4 w-4" />
            Open Scan History
          </Link>
        </div>
      </div>
    );
  }

  const theme = RISK_BANNER_STYLES[scanResult.risk_level] || RISK_BANNER_STYLES.Suspicious;
  const BannerIcon = theme.Icon;
  const confidenceValue = Math.min(100, Math.max(0, Number(scanResult.confidence_percentage) || 0));

  return (
    <div className="space-y-6">
      {/* Header Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link
            to="/dashboard"
            className="mb-2 inline-flex items-center gap-1.5 text-xs font-medium text-sky-400 hover:text-sky-300"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to QR Scanner
          </Link>
          <h1 className="text-2xl font-bold tracking-tight text-white">Scan Analysis Report</h1>
        </div>

        <div className="flex flex-wrap gap-2.5">
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2 text-xs font-semibold text-white shadow-cyber transition hover:from-blue-500 hover:to-violet-500"
          >
            <QrCode className="h-4 w-4" />
            Scan Another QR
          </Link>
          <Link
            to="/history"
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-navy-800 px-4 py-2 text-xs font-semibold text-slate-200 transition hover:border-indigo-500/50"
          >
            <History className="h-4 w-4 text-indigo-400" />
            View History
          </Link>
        </div>
      </div>

      {/* Primary Risk Assessment Banner */}
      <section className={`rounded-2xl border p-6 shadow-panel ${theme.border}`}>
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div className="flex items-start gap-4">
            <div className={`rounded-xl bg-navy-950/60 p-3 ${theme.iconColor}`}>
              <BannerIcon className="h-8 w-8" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <PredictionBadge prediction={scanResult.prediction} />
                <RiskLevelBadge riskLevel={scanResult.risk_level} />
                <span className="font-mono text-xs text-slate-400">
                  Scan #{scanResult.scan_id}
                </span>
              </div>
              <p className="mt-2 text-sm font-medium text-slate-100">{theme.summary}</p>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800/80 bg-navy-950/70 px-4 py-3 text-left sm:text-right">
            <span className="block text-[11px] font-medium uppercase tracking-wider text-slate-400">
              Model Confidence
            </span>
            <span className="text-2xl font-bold text-white">
              {confidenceValue.toFixed(2)}%
            </span>
          </div>
        </div>

        {/* Confidence Visual Bar */}
        <div className="mt-5">
          <div className="mb-1.5 flex items-center justify-between text-xs text-slate-300">
            <span>Random Forest Confidence Score</span>
            <span className="font-mono">{confidenceValue.toFixed(2)}%</span>
          </div>
          <div className="h-2.5 w-full overflow-hidden rounded-full bg-navy-950/80">
            <div
              className={`h-full rounded-full transition-all duration-500 ${theme.barColor}`}
              style={{ width: `${confidenceValue}%` }}
            />
          </div>
        </div>
      </section>

      {/* Extracted URL Display (Inert / Non-Clickable) */}
      <section className="rounded-2xl border border-slate-800/90 bg-navy-900/90 p-6 shadow-panel">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-base font-semibold text-white">Decoded QR Payload</h2>
          <span className="rounded-full border border-slate-700 bg-navy-950 px-2.5 py-0.5 text-[11px] text-slate-400">
            Never auto-opened
          </span>
        </div>

        <SafeUrlBox url={scanResult.url} />

        {/* Duplicate Scan & Cryptographic Metadata */}
        <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-navy-950/60 p-4">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <Info className="h-4 w-4 text-sky-400" />
              Previous Scan Check
            </div>
            {scanResult.previously_scanned ? (
              <div className="mt-2">
                <span className="inline-flex items-center gap-1.5 rounded-md border border-indigo-500/35 bg-indigo-500/15 px-2.5 py-1 text-xs font-semibold text-indigo-200">
                  Previously Scanned ({scanResult.previous_scan_count} prior scan
                  {scanResult.previous_scan_count === 1 ? "" : "s"})
                </span>
                <p className="mt-1.5 text-xs text-slate-400">
                  Matched via your account&apos;s SHA-256 URL fingerprint history.
                </p>
              </div>
            ) : (
              <div className="mt-2">
                <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-navy-900 px-2.5 py-1 text-xs font-semibold text-slate-300">
                  First Time Scanned
                </span>
                <p className="mt-1.5 text-xs text-slate-400">
                  This URL has not been scanned previously under your account.
                </p>
              </div>
            )}
          </div>

          <div className="rounded-xl border border-slate-800 bg-navy-950/60 p-4">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <Fingerprint className="h-4 w-4 text-violet-400" />
              SHA-256 Fingerprint &amp; Encrypted Vault
            </div>
            <p className="mt-2 break-all font-mono text-xs text-slate-300">
              {scanResult.url_fingerprint}
            </p>
            <p className="mt-1.5 text-[11px] text-slate-500">
              Stored encrypted via AES-256-GCM at {new Date(scanResult.scanned_at).toLocaleString()}
            </p>
          </div>
        </div>
      </section>

      {/* Security Warnings Section */}
      <section className="rounded-2xl border border-slate-800/90 bg-navy-900/90 p-6 shadow-panel">
        <h2 className="text-base font-semibold text-white">Security Warnings &amp; Indicators</h2>

        {Array.isArray(scanResult.warnings) && scanResult.warnings.length > 0 ? (
          <ul className="mt-4 space-y-2.5">
            {scanResult.warnings.map((warning, idx) => (
              <li
                key={idx}
                className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-sm text-amber-100"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
                <span>{warning}</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="mt-4 flex items-center gap-3 rounded-xl border border-emerald-500/25 bg-emerald-500/5 p-4 text-sm text-emerald-200">
            <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
            <span>No lexical red-flag warnings were triggered for this URL.</span>
          </div>
        )}
      </section>
    </div>
  );
}
