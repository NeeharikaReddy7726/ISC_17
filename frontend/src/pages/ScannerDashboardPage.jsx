import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  AlertCircle,
  ArrowRight,
  Cpu,
  FileImage,
  Fingerprint,
  History,
  Lock,
  QrCode,
  ShieldCheck,
  Trash2,
  UploadCloud
} from "lucide-react";
import { fetchScanHistory, scanQrImage } from "../api/client";
import { LAST_SCAN_STORAGE_KEY, useAuth } from "../context/AuthContext";
import LoadingSpinner from "../components/LoadingSpinner";
import { PredictionBadge, RiskLevelBadge } from "../components/RiskBadge";

const ALLOWED_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp"];
const ALLOWED_MIME_TYPES = ["image/png", "image/jpeg", "image/webp"];
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB matching backend constraint

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function ScannerDashboardPage() {
  const { token, user } = useAuth();
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  const [recentScans, setRecentScans] = useState([]);
  const [loadingRecent, setLoadingRecent] = useState(true);

  // Clean up object URLs on file change or unmount
  useEffect(() => {
    return () => {
      if (previewUrl) {
        URL.revokeObjectURL(previewUrl);
      }
    };
  }, [previewUrl]);

  // Load latest 3 scans for dashboard summary
  useEffect(() => {
    let active = true;

    async function loadRecent() {
      if (!token) return;
      setLoadingRecent(true);
      try {
        const items = await fetchScanHistory(token);
        if (active && Array.isArray(items)) {
          setRecentScans(items.slice(0, 3));
        }
      } catch {
        // Silent in summary widget; full error UI lives on History page
      } finally {
        if (active) setLoadingRecent(false);
      }
    }

    loadRecent();
    return () => {
      active = false;
    };
  }, [token]);

  function handleFileSelection(file) {
    setError(null);
    if (!file) return;

    const lowerName = file.name.toLowerCase();
    const hasValidExt = ALLOWED_EXTENSIONS.some((ext) => lowerName.endsWith(ext));
    if (!hasValidExt) {
      setError("Unsupported file extension. Please upload a PNG, JPG, JPEG, or WEBP image.");
      return;
    }

    if (file.type && !ALLOWED_MIME_TYPES.includes(file.type)) {
      setError(`Unsupported file type (${file.type}). Allowed types: PNG, JPG, JPEG, WEBP.`);
      return;
    }

    if (file.size === 0) {
      setError("The selected file is empty (0 bytes).");
      return;
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setError("File exceeds the 5 MB maximum upload limit.");
      return;
    }

    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }

    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
  }

  function clearSelectedFile() {
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
    setSelectedFile(null);
    setPreviewUrl(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const dropped = e.dataTransfer?.files?.[0];
    if (dropped) {
      handleFileSelection(dropped);
    }
  }

  async function handleScanSubmit(e) {
    e.preventDefault();
    if (!selectedFile) {
      setError("Please select a QR code image before starting the scan.");
      return;
    }

    setError(null);
    setScanning(true);

    try {
      const scanResult = await scanQrImage(selectedFile, token);
      sessionStorage.setItem(LAST_SCAN_STORAGE_KEY, JSON.stringify(scanResult));
      navigate("/results", { state: { scanResult } });
    } catch (err) {
      setError(err.message || "Failed to scan the uploaded QR code image.");
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Dashboard Hero Banner */}
      <section className="rounded-2xl border border-slate-800/90 bg-gradient-to-br from-navy-900 via-navy-900 to-indigo-950/40 p-6 shadow-panel">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
          <div>
            <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-sky-500/30 bg-sky-500/10 px-3 py-1 text-xs font-semibold text-sky-300">
              <ShieldCheck className="h-3.5 w-3.5" />
              Protected Scanning Environment
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-white sm:text-3xl">
              QR Security Scanner
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Upload any QR code image to inspect its embedded URL without visiting the destination.
              {user ? ` Signed in as ${user.email}.` : ""}
            </p>
          </div>

          <Link
            to="/history"
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-navy-800 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:border-indigo-500/50 hover:text-white"
          >
            <History className="h-4 w-4 text-indigo-400" />
            View Encrypted History
          </Link>
        </div>

        {/* 4-Stage Security Pipeline Strip */}
        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { Icon: QrCode, title: "1. OpenCV Decode", desc: "Static local image extraction" },
            { Icon: Cpu, title: "2. Random Forest AI", desc: "14 lexical phishing features" },
            { Icon: Fingerprint, title: "3. SHA-256 Fingerprint", desc: "Repeat scan detection" },
            { Icon: Lock, title: "4. AES-256-GCM Vault", desc: "Encrypted history storage" }
          ].map(({ Icon, title, desc }) => (
            <div
              key={title}
              className="flex items-start gap-3 rounded-xl border border-slate-800/80 bg-navy-950/60 p-3.5"
            >
              <div className="rounded-lg border border-indigo-500/30 bg-indigo-500/10 p-2 text-sky-400">
                <Icon className="h-4 w-4" />
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-200">{title}</p>
                <p className="mt-0.5 text-[11px] text-slate-400">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Main Workspace Grid: Upload & Recent Scans */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Scanner Upload Form (2 cols) */}
        <section className="rounded-2xl border border-slate-800/90 bg-navy-900/90 p-6 shadow-panel lg:col-span-2">
          <h2 className="text-lg font-semibold text-white">Upload QR Code Image</h2>
          <p className="mt-1 text-xs text-slate-400">
            Supported formats: PNG, JPG, JPEG, WEBP (max 5 MB). URLs are strictly analyzed offline.
          </p>

          {error && (
            <div className="mt-4 flex items-start gap-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3.5 text-xs text-rose-200">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleScanSubmit} className="mt-5 space-y-5">
            {/* Hidden File Input */}
            <input
              ref={fileInputRef}
              id="qr-file-input"
              type="file"
              accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
              onChange={(e) => handleFileSelection(e.target.files?.[0])}
              className="hidden"
            />

            {/* Dropzone or Image Preview */}
            {!selectedFile ? (
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragActive(true);
                }}
                onDragLeave={() => setDragActive(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    fileInputRef.current?.click();
                  }
                }}
                className={`flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed px-6 py-12 text-center transition ${
                  dragActive
                    ? "border-sky-400 bg-sky-500/10"
                    : "border-slate-700/80 bg-navy-950/60 hover:border-indigo-500/60 hover:bg-navy-950"
                }`}
              >
                <div className="mb-3 rounded-2xl border border-indigo-500/30 bg-indigo-500/10 p-3.5 text-sky-400">
                  <UploadCloud className="h-8 w-8" />
                </div>
                <p className="text-sm font-semibold text-slate-200">
                  Drop a QR code image here, or <span className="text-sky-400">browse files</span>
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  PNG, JPG, JPEG, WEBP up to 5 MB
                </p>
              </div>
            ) : (
              <div className="rounded-2xl border border-slate-800 bg-navy-950/70 p-4 sm:p-5">
                <div className="flex flex-col items-center gap-5 sm:flex-row">
                  <div className="flex h-44 w-44 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-slate-700/80 bg-white/95 p-2">
                    <img
                      src={previewUrl}
                      alt="Selected QR preview"
                      className="max-h-full max-w-full object-contain"
                    />
                  </div>

                  <div className="flex flex-1 flex-col justify-between gap-4 text-center sm:text-left">
                    <div>
                      <div className="inline-flex items-center gap-1.5 rounded-md border border-indigo-500/30 bg-indigo-500/10 px-2.5 py-1 text-[11px] font-medium text-indigo-300">
                        <FileImage className="h-3.5 w-3.5" />
                        Ready for Inspection
                      </div>
                      <p className="mt-2 break-all text-sm font-semibold text-white">
                        {selectedFile.name}
                      </p>
                      <p className="mt-1 text-xs text-slate-400">
                        Size: {formatFileSize(selectedFile.size)} • Type:{" "}
                        {selectedFile.type || "image"}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center justify-center gap-2.5 sm:justify-start">
                      <button
                        type="button"
                        disabled={scanning}
                        onClick={() => fileInputRef.current?.click()}
                        className="rounded-lg border border-slate-700 bg-navy-800 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-slate-500 hover:text-white disabled:opacity-50"
                      >
                        Change File
                      </button>
                      <button
                        type="button"
                        disabled={scanning}
                        onClick={clearSelectedFile}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 transition hover:bg-rose-500/20 disabled:opacity-50"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={!selectedFile || scanning}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 px-5 py-3 text-sm font-semibold text-white shadow-cyber transition hover:from-blue-500 hover:to-violet-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {scanning ? (
                <LoadingSpinner size="sm" label="Decoding QR & Analyzing Phishing Risk..." />
              ) : (
                <>
                  <QrCode className="h-4 w-4" />
                  <span>Scan &amp; Analyze QR Code</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>
        </section>

        {/* Recent Scans Quick Panel (1 col) */}
        <aside className="rounded-2xl border border-slate-800/90 bg-navy-900/90 p-6 shadow-panel">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-base font-semibold text-white">Recent Scans</h2>
            <Link
              to="/history"
              className="text-xs font-semibold text-sky-400 hover:text-sky-300"
            >
              See All
            </Link>
          </div>

          {loadingRecent ? (
            <div className="py-10">
              <LoadingSpinner size="sm" label="Decrypting recent records..." />
            </div>
          ) : recentScans.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-800 bg-navy-950/50 p-6 text-center">
              <History className="mx-auto mb-2 h-6 w-6 text-slate-600" />
              <p className="text-xs font-medium text-slate-300">No scan records yet</p>
              <p className="mt-1 text-[11px] text-slate-500">
                Your scanned QR codes will appear here encrypted with AES-256-GCM.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {recentScans.map((item) => (
                <Link
                  key={item.scan_id}
                  to={`/history/${item.scan_id}`}
                  className="block rounded-xl border border-slate-800 bg-navy-950/70 p-3.5 transition hover:border-indigo-500/40 hover:bg-navy-950"
                >
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <PredictionBadge prediction={item.prediction} />
                    <RiskLevelBadge riskLevel={item.risk_level} />
                  </div>
                  <p className="truncate font-mono text-xs text-sky-300">{item.url}</p>
                  <p className="mt-1.5 text-[11px] text-slate-500">
                    Scan #{item.scan_id} • {new Date(item.scanned_at).toLocaleString()}
                  </p>
                </Link>
              ))}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
