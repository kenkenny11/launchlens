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
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
