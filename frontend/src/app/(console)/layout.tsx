import type { Metadata, Viewport } from "next";
import { Sidebar } from "@/components/shell/Sidebar";
import { Topbar } from "@/components/shell/Topbar";
import { ClassificationBar } from "@/components/shell/ClassificationBar";
import { DatasetBanner } from "@/components/shell/DatasetBanner";

/** Branded console metadata — only applied to real dashboard routes. */
export const metadata: Metadata = {
  title: "Trapline // Central Honeypot Intelligence",
  description: "Centralized honeypot threat-intelligence overwatch console for Trapline.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#0b111c",
};

export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <ClassificationBar />
      <div className="flex min-h-[calc(100vh-26px)]">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <DatasetBanner />
          <main className="flex-1 px-5 py-5 lg:px-7">{children}</main>
        </div>
      </div>
    </>
  );
}
