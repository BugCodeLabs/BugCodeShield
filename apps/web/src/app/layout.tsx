import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BugCode Shield — All-in-one code security scanner",
  description: "Run Semgrep, Trivy, Gitleaks, and optional SonarQube from one dashboard. Scan a local folder, ZIP, or GitHub repository in place.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
