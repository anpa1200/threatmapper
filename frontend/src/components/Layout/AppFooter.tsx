export function AppFooter() {
  return (
    <footer className="flex h-6 shrink-0 items-center border-t border-gray-800 bg-mitre-navy/95 px-6 text-[10px] text-gray-500">
      <div className="flex w-full min-w-0 items-center justify-between gap-3">
        <span className="min-w-0 truncate">
          Copyright (c) {new Date().getFullYear()}{' '}
          <a
            href="https://1200km.com/about.html"
            target="_blank"
            rel="noreferrer"
            className="font-medium text-gray-400 transition-colors hover:text-mitre-accent"
          >
            Andrey Pautov
          </a>{' '}
          / 1200km. All rights reserved.
        </span>
        <a
          href="https://1200km.com"
          target="_blank"
          rel="noreferrer"
          className="shrink-0 font-medium text-gray-400 transition-colors hover:text-mitre-accent"
        >
          1200km.com
        </a>
      </div>
    </footer>
  );
}
