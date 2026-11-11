import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  AlertCircle,
  Eye,
  Fingerprint,
  History,
  Lock,
  QrCode,
  RefreshCw,
  Search,
  X
} from "lucide-react";
import { fetchScanHistory, fetchSingleScan } from "../api/client";
import { useAuth } from "../context/AuthContext";
import LoadingSpinner from "../components/LoadingSpinner";
import { PredictionBadge, RiskLevelBadge } from "../components/RiskBadge";
import SafeUrlBox from "../components/SafeUrlBox";

export default function ScanHistoryPage() {
  const { token } = useAuth();
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [records, setRecords] = useState([]);
  const [loadingList, setLoadingList] = useState(true);
  const [listError, setListError] = useState(null);

  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState("All");

  // Individual record inspection state (fetched via GET /api/history/{scan_id})
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError, setDetailError] = useState(null);

  const loadHistory = useCallback(async () => {
    if (!token) return;
    setLoadingList(true);
    setListError(null);
    try {
      const data = await fetchScanHistory(token);
      setRecords(Array.isArray(data) ? data : []);
    } catch (err) {
      setListError(err.message || "Failed to load scan history.");
    } finally {
      setLoadingList(false);
    }
  }, [token]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  // Whenever /history/:scanId is active, fetch the individual record cleanly from backend
  useEffect(() => {
    let active = true;

    async function loadSingleRecord() {
      if (!scanId || !token) {
        setSelectedRecord(null);
        setDetailError(null);
        return;
      }

      setLoadingDetail(true);
      setDetailError(null);
      try {
        const record = await fetchSingleScan(scanId, token);
        if (active) {
          setSelectedRecord(record);
        }
      } catch (err) {
        if (active) {
          setSelectedRecord(null);
          setDetailError(err.message || "Unable to retrieve the requested scan record.");
        }
      } finally {
        if (active) {
          setLoadingDetail(false);
        }
      }
    }

    loadSingleRecord();
    return () => {
      active = false;
    };
  }, [scanId, token]);

  const filteredRecords = records.filter((item) => {
    const matchesRisk = riskFilter === "All" || item.risk_level === riskFilter;
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      item.url.toLowerCase().includes(q) ||
      String(item.scan_id).includes(q) ||
      item.url_fingerprint.toLowerCase().includes(q);
    return matchesRisk && matchesSearch;
  });

  function closeDetailModal() {
    navigate("/history");
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <section className="flex flex-col justify-between gap-4 rounded-2xl border border-slate-800/90 bg-navy-900/90 p-6 shadow-panel sm:flex-row sm:items-center">
        <div>
          <div className="mb-1.5 inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-300">
            <Lock className="h-3.5 w-3.5" />
            AES-256-GCM Decrypted Per-User Vault
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">Scan History</h1>
          <p className="mt-1 text-sm text-slate-400">
            Records stored encrypted in SQLite and decrypted strictly for your authenticated account.
          </p>
        </div>

        <div className="flex flex-wrap gap-2.5">
          <button
            type="button"
            onClick={loadHistory}
            disabled={loadingList}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-navy-800 px-3.5 py-2 text-xs font-semibold text-slate-200 transition hover:border-indigo-500/50 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loadingList ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <Link
            to="/dashboard"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2 text-xs font-semibold text-white shadow-cyber transition hover:from-blue-500 hover:to-violet-500"
          >
            <QrCode className="h-4 w-4" />
            New Scan
          </Link>
        </div>
      </section>

      {/* Filter Toolbar */}
      {!loadingList && !listError && records.length > 0 && (
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative flex-1 sm:max-w-sm">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by URL, scan ID, or fingerprint..."
              className="w-full rounded-xl border border-slate-800 bg-navy-900 py-2 pl-10 pr-4 text-sm text-white placeholder-slate-500 outline-none focus:border-indigo-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            {["All", "Safe", "Suspicious", "High Risk"].map((level) => (
              <button
                key={level}
                type="button"
                onClick={() => setRiskFilter(level)}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                  riskFilter === level
                    ? "border border-indigo-500/50 bg-indigo-500/20 text-white"
                    : "border border-slate-800 bg-navy-900 text-slate-400 hover:text-slate-200"
                }`}
              >
                {level}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main List States */}
      {loadingList ? (
        <div className="rounded-2xl border border-slate-800 bg-navy-900/90 py-16">
          <LoadingSpinner size="lg" label="Decrypting your scan history..." />
        </div>
      ) : listError ? (
        <div className="rounded-2xl border border-rose-500/40 bg-rose-500/10 p-6 text-center">
          <AlertCircle className="mx-auto mb-2 h-8 w-8 text-rose-400" />
          <h2 className="text-base font-semibold text-rose-100">Could Not Load History</h2>
          <p className="mt-1 text-sm text-rose-200">{listError}</p>
          <button
            type="button"
            onClick={loadHistory}
            className="mt-4 rounded-xl border border-rose-500/40 bg-rose-500/20 px-4 py-2 text-xs font-semibold text-rose-100 hover:bg-rose-500/30"
          >
            Try Again
          </button>
        </div>
      ) : records.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-navy-900/90 p-12 text-center shadow-panel">
          <History className="mx-auto mb-3 h-10 w-10 text-slate-600" />
          <h2 className="text-lg font-semibold text-white">No Scan History Found</h2>
          <p className="mx-auto mt-1 max-w-md text-sm text-slate-400">
            You have not scanned any QR codes yet. Upload a QR code image to inspect its security risk and create your first encrypted scan record.
          </p>
          <Link
            to="/dashboard"
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-violet-600 px-5 py-2.5 text-sm font-semibold text-white shadow-cyber transition hover:from-blue-500 hover:to-violet-500"
          >
            <QrCode className="h-4 w-4" />
            Scan First QR Code
          </Link>
        </div>
      ) : filteredRecords.length === 0 ? (
        <div className="rounded-2xl border border-slate-800 bg-navy-900/90 p-8 text-center">
          <p className="text-sm text-slate-300">No scan records match your current filters.</p>
        </div>
      ) : (
        <>
          {/* Desktop Table View */}
          <div className="hidden overflow-hidden rounded-2xl border border-slate-800/90 bg-navy-900/90 shadow-panel md:block">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800 bg-navy-950/70 text-xs uppercase tracking-wider text-slate-400">
                    <th className="px-5 py-3.5 font-semibold">ID</th>
                    <th className="px-5 py-3.5 font-semibold">Decoded URL</th>
                    <th className="px-5 py-3.5 font-semibold">Prediction</th>
                    <th className="px-5 py-3.5 font-semibold">Risk Level</th>
                    <th className="px-5 py-3.5 font-semibold">Scan Date</th>
                    <th className="px-5 py-3.5 text-right font-semibold">Inspect</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {filteredRecords.map((item) => (
                    <tr
                      key={item.scan_id}
                      className="transition hover:bg-navy-800/40"
                    >
                      <td className="whitespace-nowrap px-5 py-4 font-mono text-xs text-slate-400">
                        #{item.scan_id}
                      </td>
                      <td className="max-w-xs px-5 py-4">
                        <span className="block truncate font-mono text-xs text-sky-300">
                          {item.url}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-5 py-4">
                        <PredictionBadge prediction={item.prediction} />
                      </td>
                      <td className="whitespace-nowrap px-5 py-4">
                        <RiskLevelBadge riskLevel={item.risk_level} />
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-400">
                        {new Date(item.scanned_at).toLocaleString()}
                      </td>
                      <td className="whitespace-nowrap px-5 py-4 text-right">
                        <button
                          type="button"
                          onClick={() => navigate(`/history/${item.scan_id}`)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-navy-950 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-indigo-500/60 hover:text-white"
                        >
                          <Eye className="h-3.5 w-3.5 text-sky-400" />
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Mobile Stacked Card View */}
          <div className="space-y-3 md:hidden">
            {filteredRecords.map((item) => (
              <div
                key={item.scan_id}
                className="rounded-2xl border border-slate-800 bg-navy-900/90 p-4 shadow-panel"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-slate-400">Scan #{item.scan_id}</span>
                  <span className="text-[11px] text-slate-500">
                    {new Date(item.scanned_at).toLocaleString()}
                  </span>
                </div>

                <p className="mt-2 truncate font-mono text-xs text-sky-300">{item.url}</p>

                <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <PredictionBadge prediction={item.prediction} />
                    <RiskLevelBadge riskLevel={item.risk_level} />
                  </div>

                  <button
                    type="button"
                    onClick={() => navigate(`/history/${item.scan_id}`)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-navy-950 px-3 py-1.5 text-xs font-medium text-slate-200"
                  >
                    <Eye className="h-3.5 w-3.5 text-sky-400" />
                    Details
                  </button>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Individual Record Inspection Modal (GET /api/history/{scan_id}) */}
      {scanId && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
          aria-labelledby="record-inspector-title"
        >
          <div className="w-full max-w-2xl rounded-2xl border border-slate-700/80 bg-navy-900 p-6 shadow-panel">
            <div className="mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h2 id="record-inspector-title" className="text-lg font-bold text-white">
                  Scan Record #{scanId}
                </h2>
                <p className="text-xs text-slate-400">
                  Decrypted dynamically via GET /api/history/{scanId}
                </p>
              </div>
              <button
                type="button"
                onClick={closeDetailModal}
                className="rounded-lg border border-slate-700 bg-navy-950 p-1.5 text-slate-400 hover:text-white"
                aria-label="Close record details"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {loadingDetail ? (
              <div className="py-12">
                <LoadingSpinner size="md" label="Decrypting record..." />
              </div>
            ) : detailError ? (
              <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-5 text-center">
                <AlertCircle className="mx-auto mb-2 h-7 w-7 text-rose-400" />
                <p className="text-sm font-medium text-rose-200">{detailError}</p>
                <button
                  type="button"
                  onClick={closeDetailModal}
                  className="mt-4 rounded-lg border border-slate-700 bg-navy-800 px-4 py-2 text-xs font-semibold text-slate-200"
                >
                  Back to History
                </button>
              </div>
            ) : selectedRecord ? (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2.5">
                  <PredictionBadge prediction={selectedRecord.prediction} />
                  <RiskLevelBadge riskLevel={selectedRecord.risk_level} />
                  <span className="text-xs text-slate-400">
                    Scanned on {new Date(selectedRecord.scanned_at).toLocaleString()}
                  </span>
                </div>

                <SafeUrlBox url={selectedRecord.url} label="Decrypted URL (Read-Only)" />

                <div className="rounded-xl border border-slate-800 bg-navy-950/60 p-4">
                  <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                    <Fingerprint className="h-4 w-4 text-violet-400" />
                    SHA-256 Fingerprint
                  </div>
                  <p className="mt-1.5 break-all font-mono text-xs text-slate-300">
                    {selectedRecord.url_fingerprint}
                  </p>
                </div>

                <div className="flex justify-end pt-2">
                  <button
                    type="button"
                    onClick={closeDetailModal}
                    className="rounded-xl border border-slate-700 bg-navy-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:border-indigo-500/50 hover:text-white"
                  >
                    Close Inspector
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
