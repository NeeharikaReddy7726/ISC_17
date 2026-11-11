import { Loader2 } from "lucide-react";

export default function LoadingSpinner({ label = "Loading...", size = "md" }) {
  const sizes = {
    sm: "h-4 w-4",
    md: "h-6 w-6",
    lg: "h-10 w-10"
  };

  return (
    <div className="flex flex-col items-center justify-center gap-3 text-slate-300" role="status">
      <Loader2 className={`${sizes[size] || sizes.md} animate-spin text-indigo-400`} />
      {label && <span className="text-sm font-medium tracking-wide text-slate-300">{label}</span>}
    </div>
  );
}
