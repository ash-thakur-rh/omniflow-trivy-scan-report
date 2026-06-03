import type { Metadata } from 'next';
import { Suspense } from 'react';
import './globals.css';
import Link from 'next/link';
import ThemeSync from '@/components/ThemeSync';
import { FilterProvider, FilterBar } from '@agnistack/omniflow-ui';

export const metadata: Metadata = {
  title: 'Trivy Scan Report — OmniFlow',
};

const NAV = [
  { href: '/',                label: 'Overview' },
  { href: '/vulnerabilities', label: 'Vulnerabilities' },
  { href: '/packages',        label: 'Packages' },
  { href: '/compare',         label: 'Compare' },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: `(function(){var p=new URLSearchParams(location.search).get('theme'),t=p||sessionStorage.getItem('omniflow-plugin-theme'),s=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';if(p)sessionStorage.setItem('omniflow-plugin-theme',p);if((t||s)==='dark')document.documentElement.classList.add('dark')})()` }} />
      </head>
      <body className="min-h-screen flex flex-col">
        <ThemeSync />
        <header className="bg-white dark:bg-slate-900 border-b border-gray-200 dark:border-slate-800 px-6 py-3 flex items-center gap-4 flex-shrink-0">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span className="text-sm font-bold text-gray-900 dark:text-slate-100">Trivy Scan Report</span>
          <span className="text-xs bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-900 px-2 py-0.5 rounded-full">OmniFlow Plugin</span>
          <nav className="ml-4 flex gap-1">
            {NAV.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className="text-xs px-3 py-1.5 rounded-md text-gray-500 dark:text-slate-400 hover:text-gray-900 dark:hover:text-slate-100 hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors"
              >
                {label}
              </Link>
            ))}
          </nav>
        </header>
        <FilterProvider defaultLimit="50">
          <Suspense><FilterBar apiType="trivy-scan-report" defaultLimit="50" limitOptions={[{ value: '10', label: 'Last 10' }, { value: '20', label: 'Last 20' }, { value: '50', label: 'Last 50' }, { value: '100', label: 'Last 100' }]} /></Suspense>
          <main className="flex-1 p-6">{children}</main>
        </FilterProvider>
      </body>
    </html>
  );
}