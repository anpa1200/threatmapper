import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { getHelpTopicByPath, getHelpTopicByTitle } from '@/config/help';

export function ModuleHelpButton({ title }: { title: string }) {
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const topic = getHelpTopicByPath(location.pathname) ?? getHelpTopicByTitle(title);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open]);

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(value => !value)}
        className="rounded border border-gray-700 bg-gray-900 px-3 py-1.5 text-xs font-semibold text-gray-300 transition-colors hover:border-mitre-accent hover:text-white"
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        ? Help
      </button>
      {open && (
        <>
          <button
            type="button"
            className="fixed inset-0 z-40 cursor-default bg-transparent"
            aria-label="Close module help"
            onClick={() => setOpen(false)}
          />
          <section
            role="dialog"
            aria-label={`${topic.title} help`}
            className="absolute right-0 top-10 z-50 w-[min(28rem,calc(100vw-2rem))] max-h-[calc(100vh-6rem)] overflow-y-auto rounded-lg border border-gray-700 bg-gray-950 p-4 text-sm shadow-2xl"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-mitre-accent">Module guide</p>
                <h2 className="mt-1 text-lg font-semibold text-white">{topic.title}</h2>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-400 hover:border-gray-500 hover:text-white"
              >
                Close
              </button>
            </div>

            <p className="mt-3 leading-6 text-gray-300">{topic.summary}</p>

            <HelpList title="Use this when" items={topic.whenToUse.slice(0, 3)} />
            <HelpList title="Basic workflow" items={topic.workflow.slice(0, 4)} ordered />
            <HelpList title="Main outputs" items={topic.outputs.slice(0, 3)} />

            <div className="mt-4 rounded border border-amber-500/30 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
              {topic.tips[0]}
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              <Link
                to={`/help#${topic.id}`}
                onClick={() => setOpen(false)}
                className="rounded bg-mitre-accent px-3 py-2 text-xs font-semibold text-white hover:bg-mitre-accent/90"
              >
                Open full help
              </Link>
              <Link
                to={topic.route}
                onClick={() => setOpen(false)}
                className="rounded border border-gray-700 px-3 py-2 text-xs font-semibold text-gray-300 hover:border-gray-500 hover:text-white"
              >
                Open module
              </Link>
            </div>
          </section>
        </>
      )}
    </div>
  );
}

function HelpList({ title, items, ordered = false }: { title: string; items: string[]; ordered?: boolean }) {
  const ListTag = ordered ? 'ol' : 'ul';
  return (
    <div className="mt-4">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
      <ListTag className={`mt-2 space-y-1 text-gray-300 ${ordered ? 'list-decimal pl-5' : 'list-disc pl-5'}`}>
        {items.map(item => (
          <li key={item} className="leading-5">
            {item}
          </li>
        ))}
      </ListTag>
    </div>
  );
}
