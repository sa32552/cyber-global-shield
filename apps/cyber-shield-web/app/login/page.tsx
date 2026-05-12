"use client";

import { useState, FormEvent, useEffect } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("");

  // Check if already logged in
  useEffect(() => {
    const checkSession = async () => {
      const supabase = createClient();
      const { data } = await supabase.auth.getSession();
      if (data.session) {
        router.push("/");
      }
    };
    checkSession();
  }, [router]);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const supabase = createClient();

      if (mode === "login") {
        const { data, error: authError } = await supabase.auth.signInWithPassword({
          email,
          password,
        });

        if (authError) {
          throw new Error(authError.message);
        }

        if (data.session) {
          // Store the access token for API calls
          localStorage.setItem("token", data.session.access_token);
          router.push("/");
        }
      } else {
        // Register mode
        const { data, error: authError } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: {
              full_name: fullName,
              org_name: orgName,
              role: "analyst",
            },
          },
        });

        if (authError) {
          throw new Error(authError.message);
        }

        // Also register via backend API to create org + profile
        try {
          const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
          await fetch(`${apiUrl}/api/v1/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email,
              password,
              full_name: fullName,
              org_name: orgName,
              role: "analyst",
            }),
          });
        } catch {
          // Backend registration is optional — Supabase handles the auth
        }

        setError(
          "Inscription réussie ! Vérifiez votre email pour confirmer votre compte."
        );
        setMode("login");
      }
    } catch (err: any) {
      setError(err.message ?? "Échec de l'authentification");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">CG</div>
        <h1 className="login-title">Cyber Global Shield</h1>
        <p className="login-subtitle">SOC Dashboard — Authentification</p>

        {error && (
          <div
            className={`login-error ${
              error.includes("r\u00e9ussie") ? "login-success" : ""
            }`}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} className="login-form">
          {mode === "register" && (
            <div className="form-group">
              <label htmlFor="fullName">Nom complet</label>
              <input
                id="fullName"
                type="text"
                className="form-input"
                placeholder="Jean Dupont"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
              />
            </div>
          )}

          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              className="form-input"
              placeholder="admin@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoFocus
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Mot de passe</label>
            <input
              id="password"
              type="password"
              className="form-input"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {mode === "register" && (
            <div className="form-group">
              <label htmlFor="orgName">Organisation (optionnel)</label>
              <input
                id="orgName"
                type="text"
                className="form-input"
                placeholder="Ma PME"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
              />
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary login-btn"
            disabled={loading}
          >
            {loading
              ? "Connexion en cours…"
              : mode === "login"
              ? "Se connecter"
              : "Créer un compte"}
          </button>
        </form>

        <div className="login-toggle">
          {mode === "login" ? (
            <button
              type="button"
              className="btn-link"
              onClick={() => {
                setMode("register");
                setError(null);
              }}
            >
              Pas encore de compte ? S&rsquo;inscrire
            </button>
          ) : (
            <button
              type="button"
              className="btn-link"
              onClick={() => {
                setMode("login");
                setError(null);
              }}
            >
              Déjà un compte ? Se connecter
            </button>
          )}
        </div>

        <p className="login-footer">
          Plateforme SIEM autonome v2.0 &mdash; Sécurisé par Supabase Auth
        </p>
      </div>
    </div>
  );
}
