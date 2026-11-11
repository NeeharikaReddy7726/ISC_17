import { AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react";

const RISK_STYLES = {
  Safe: {
    container: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
    dot: "bg-emerald-400",
    Icon: CheckCircle2
  },
  Suspicious: {
    container: "bg-amber-500/10 text-amber-300 border-amber-500/30",
    dot: "bg-amber-400",
    Icon: AlertTriangle
  },
  "High Risk": {
    container: "bg-rose-500/10 text-rose-300 border-rose-500/30",
    dot: "bg-rose-400",
    Icon: ShieldAlert
  }
};

const PREDICTION_STYLES = {
  Legitimate: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  Phishing: "bg-rose-500/15 text-rose-300 border-rose-500/30"
};

export function RiskLevelBadge({ riskLevel }) {
  const style = RISK_STYLES[riskLevel] || {
    container: "bg-slate-700/40 text-slate-300 border-slate-600/40",
    dot: "bg-slate-400",
    Icon: AlertTriangle
  };
  const { Icon } = style;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold tracking-wide ${style.container}`}
    >
      <Icon className="h-3.5 w-3.5" />
      {riskLevel}
    </span>
  );
}

export function PredictionBadge({ prediction }) {
  const style =
    PREDICTION_STYLES[prediction] || "bg-slate-700/40 text-slate-300 border-slate-600/40";

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold uppercase tracking-wider ${style}`}
    >
      {prediction}
    </span>
  );
}
