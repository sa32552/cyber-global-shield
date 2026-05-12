import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cyber Global Shield — SOC Dashboard",
  description:
    "Plateforme SIEM autonome avec détection zero-day, ML, agents CrewAI, SOAR et 35 modules de sécurité.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
