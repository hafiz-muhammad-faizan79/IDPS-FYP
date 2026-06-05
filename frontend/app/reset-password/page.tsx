"use client";
import { useState, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { Eye, EyeOff, Shield, Lock, AlertTriangle, CheckCircle } from "lucide-react";

function ResetPasswordContent() {
  const params  = useSearchParams();
  const router  = useRouter();
  const token   = params.get("token") || "";

  const [password, setPassword]       = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const [showPass, setShowPass]       = useState(false);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState("");
  const [success, setSuccess]         = useState(false);

  useEffect(() => {
    if (!token) setError("Invalid reset link — no token provided");
  }, [token]);

  const strength = (() => {
    if (!password) return { score: 0, label: "", color: "#475569" };
    let s = 0;
    if (password.length >= 8)         s++;
    if (password.length >= 12)        s++;
    if (/[A-Z]/.test(password))       s++;
    if (/[0-9]/.test(password))       s++;
    if (/[^A-Za-z0-9]/.test(password)) s++;
    if (s <= 2) return { score: s, label: "WEAK",        color: "#ff006e" };
    if (s <= 3) return { score: s, label: "FAIR",        color: "#f59e0b" };
    if (s <= 4) return { score: s, label: "STRONG",      color: "#00d4ff" };
    return        { score: s, label: "VERY STRONG", color: "#00ff9f" };
  })();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password.length < 8)       return setError("Password must be at least 8 characters");
    if (!/[A-Z]/.test(password))   return setError("Password must contain at least one uppercase letter");
    if (!/[0-9]/.test(password))   return setError("Password must contain at least one number");
    if (password !== confirmPass)  return setError("Passwords do not match");

    setLoading(true);
    try {
      const res = await fetch("fyp-backend-production-944f.up.railway.app/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || "Reset failed");
        setLoading(false);
        return;
      }
      setSuccess(true);
      setTimeout(() => router.push("/login"), 3000);
    } catch {
      setError("Connection failed — backend unreachable");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md p-8 rounded-lg" style={{
        background: "rgba(6, 10, 20, 0.97)",
        border:     "1px solid rgba(0, 212, 255, 0.2)",
        boxShadow:  "0 0 60px rgba(0, 212, 255, 0.08)",
      }}>
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 mb-3 relative">
            <div className="absolute inset-0 rounded-full" style={{
              background: "radial-gradient(circle, rgba(0,212,255,0.15), transparent)",
              border:     "1px solid rgba(0, 212, 255, 0.3)",
            }} />
            <Shield size={28} className="text-cyan-400 relative z-10" />
          </div>
          <h1 className="text-2xl font-bold text-cyan-400 tracking-widest" style={{ fontFamily: "'Orbitron', monospace" }}>
            Reset Password
          </h1>
          <p className="text-[11px] text-slate-500 font-mono tracking-widest mt-1 uppercase">
            Set your new access key
          </p>
        </div>

        {success ? (
          <div className="text-center py-6">
            <CheckCircle size={48} className="mx-auto text-green-400 mb-3" />
            <h2 className="text-lg font-bold text-green-400">Password Reset!</h2>
            <p className="text-sm text-slate-400 mt-2">Redirecting to login...</p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono text-slate-500 tracking-widest uppercase mb-1.5">New Password</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400 opacity-60" />
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="cyber-input w-full pl-9 pr-10 py-3 rounded text-sm"
                />
                <button type="button" onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-cyan-400">
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              {password && (
                <div className="mt-2">
                  <div className="flex gap-1">
                    {[1,2,3,4,5].map((i) => (
                      <div key={i} className="flex-1 h-1 rounded"
                        style={{ background: i <= strength.score ? strength.color : "rgba(148,163,184,0.15)" }} />
                    ))}
                  </div>
                  <p className="text-[9px] font-mono mt-1 tracking-widest" style={{ color: strength.color }}>
                    {strength.label} • Min: 8 chars + uppercase + number
                  </p>
                </div>
              )}
            </div>

            <div>
              <label className="block text-[10px] font-mono text-slate-500 tracking-widest uppercase mb-1.5">Confirm Password</label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400 opacity-60" />
                <input
                  type={showPass ? "text" : "password"}
                  value={confirmPass}
                  onChange={(e) => setConfirmPass(e.target.value)}
                  placeholder="••••••••••••"
                  className="cyber-input w-full pl-9 pr-4 py-3 rounded text-sm"
                />
              </div>
              {confirmPass && password !== confirmPass && (
                <p className="text-[9px] font-mono mt-1 text-red-400">✗ Passwords do not match</p>
              )}
              {confirmPass && password === confirmPass && (
                <p className="text-[9px] font-mono mt-1 text-green-400">✓ Passwords match</p>
              )}
            </div>

            {error && (
              <div className="flex items-center gap-2 px-3 py-2 rounded text-[11px] font-mono text-red-400"
                style={{ background: "rgba(255,0,110,0.08)", border: "1px solid rgba(255,0,110,0.25)" }}>
                <AlertTriangle size={12} />{error}
              </div>
            )}

            <button type="submit" disabled={loading || !token}
              className="cyber-btn w-full py-3 rounded text-sm font-bold tracking-widest disabled:opacity-50">
              {loading ? "RESETTING..." : "RESET PASSWORD"}
            </button>

            <div className="text-center pt-2">
              <button type="button" onClick={() => router.push("/login")}
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline tracking-wider">
                BACK TO LOGIN
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-cyan-400">Loading...</div>}>
      <ResetPasswordContent />
    </Suspense>
  );
}
