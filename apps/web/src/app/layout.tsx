import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BugCode Shield — All-in-one code security scanner",
  description: "Code check, vulnerability check, security hotspot check, and secret leak check from Semgrep, Trivy, Gitleaks, and SonarQube in one dashboard.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
