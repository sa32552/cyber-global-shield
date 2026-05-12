"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  {
    section: "Général",
    items: [
      { href: "/", label: "Dashboard", icon: "📊" },
      { href: "/alerts", label: "Alertes", icon: "🔔", badge: true },
      { href: "/incidents", label: "Incidents", icon: "🚨" },
    ],
  },
  {
    section: "Sécurité",
    items: [
      { href: "/threats", label: "Menaces", icon: "🌍" },
      { href: "/soar", label: "Playbooks SOAR", icon: "⚡" },
    ],
  },
  {
    section: "Système",
    items: [
      { href: "/settings", label: "Configuration", icon: "⚙️" },
    ],
  },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="page-shell">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <div className="sidebar-logo-icon">CG</div>
          <div>
            <div className="sidebar-logo-text">Cyber Global Shield</div>
            <div className="sidebar-logo-sub">SOC Platform v2.0</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((section) => (
            <div key={section.section}>
              <div className="sidebar-section">{section.section}</div>
              {section.items.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`nav-link ${isActive ? "active" : ""}`}
                  >
                    <span className="nav-link-icon">{item.icon}</span>
                    {item.label}
                    {item.badge && <span className="nav-link-badge">3</span>}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>

        <div style={{ padding: "16px 12px", borderTop: "1px solid var(--border-color)", marginTop: "auto" }}>
          <div className="nav-link">
            <span className="nav-link-icon">🔌</span>
            <span style={{ fontSize: 12, color: "var(--accent-green)" }}>● Connecté</span>
          </div>
        </div>
      </aside>

      <main className="content">{children}</main>
    </div>
  );
}
