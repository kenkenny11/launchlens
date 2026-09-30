import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LaunchLens — AI App Launch Risk Scanner",
  description: "Scan your public web app for observable security, reliability, UX, and SEO signals.",
  metadataBase: new URL("https://launchlens-liart.vercel.app"),
  openGraph: {
    title: "LaunchLens — AI App Launch Risk Scanner",
    description: "Scan your public web app for observable launch risks and get an AI-ready fix prompt.",
    url: "https://launchlens-liart.vercel.app",
    siteName: "LaunchLens",
    type: "website",
  },
  twitter: {
    card: "summary",
    title: "LaunchLens — AI App Launch Risk Scanner",
    description: "Scan your public web app for observable launch risks and get an AI-ready fix prompt.",
  },
  other: {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' https://api.groq.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
