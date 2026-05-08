import Link from "next/link";

const links = [
  { href: "/", label: "Overview" },
  { href: "/services", label: "Services" },
  { href: "/alerts", label: "Alerts" },
];

export function AppShell({
  children,
  activePath,
}: {
  children: React.ReactNode;
  activePath: string;
}) {
  return (
    <div className="page-shell">
      <aside className="sidebar">
        <div className="brand">AI Incident Layer</div>
        <div className="brand-title">Business-first reliability.</div>
        <nav className="nav-stack">
          {links.map((link) => (
            <Link key={link.href} href={link.href} className={`nav-link ${activePath === link.href ? "active" : ""}`}>
              {link.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}