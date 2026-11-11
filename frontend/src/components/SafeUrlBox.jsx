import { useState } from "react";
import { Check, Copy, Lock } from "lucide-react";

/**
 * Safely displays a decoded URL purely as inert text (`<code>`) with a Copy button.
 * Intentionally avoids `<a>` tags or navigation so users cannot accidentally click
 * or open potentially malicious phishing links.
 */
export default function SafeUrlBox({ url, label = "Extracted URL (Static Inspection Only)" }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may be unavailable on non-HTTPS contexts in older browsers
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-navy-950/80 p-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
          <Lock className="h-3.5 w-3.5 text-indigo-400" />
          {label}
        </span>

        <button
          type="button"
          onClick={handleCopy}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-navy-800 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-indigo-500/50 hover:text-white"
        >
          {copied ? (
            <>
              <Check className="h-3.5 w-3.5 text-emerald-400" />
              Copied
            </>
          ) : (
            <>
              <Copy className="h-3.5 w-3.5" />
              Copy Text
            </>
          )}
        </button>
      </div>

      <code className="block break-all font-mono text-sm leading-relaxed text-sky-300 select-all">
        {url}
      </code>
    </div>
  );
}
